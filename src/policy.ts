/**
 * Deterministic policy: canonicalization, target extraction, scope, and rules.
 *
 * Everything here runs before any model call and decides, without an LLM, whether
 * a call is denied outright, may skip judgment on an exact grant, is a safe local
 * read, or must be judged.
 *
 * The security-relevant invariants:
 *
 * - **Hashes cover complete bytes.** Sampling for the judge prompt happens later
 *   and never feeds the hash, so an oversized payload cannot dodge grant binding.
 * - **An unresolved target never matches an allow.** If we could not resolve where
 *   a call points, we do not get to claim a human already approved that place.
 * - **Any wildcard demotes an allow to posture.** Only a fully specified canonical
 *   call may skip the judge; a single `*` makes the rule a hint, permanently.
 */

import { createHash } from "node:crypto";
import { existsSync, realpathSync } from "node:fs";
import path from "node:path";
import type {
	CallScope,
	CallTarget,
	CanonicalCall,
	PolicyRule,
	RiskClass,
	RuleSuggestion,
	ToolTier,
} from "./contracts.ts";

// ---------------------------------------------------------------------------
// Canonical JSON and hashing
// ---------------------------------------------------------------------------

/**
 * Deterministic JSON: NFC-normalized strings, sorted object keys, preserved array
 * order, and type-distinguishing encoding so `1`, `"1"`, and `true` never collide.
 *
 * No truncation happens anywhere in this function. The hash it feeds is the
 * identity a human approval is bound to, so it must cover every byte the model
 * actually asked for.
 */
export function canonicalize(value: unknown): string {
	if (value === null) return "null";
	if (value === undefined) return "undef";
	switch (typeof value) {
		case "string":
			return `s:${JSON.stringify(value.normalize("NFC"))}`;
		case "number":
			return Number.isFinite(value) ? `n:${value}` : "n:nonfinite";
		case "boolean":
			return `b:${value}`;
		case "bigint":
			return `n:${value}`;
		default:
			break;
	}
	if (Array.isArray(value)) {
		return `a:[${value.map(canonicalize).join(",")}]`;
	}
	if (typeof value === "object") {
		const entries = Object.entries(value as Record<string, unknown>)
			.filter(([, v]) => v !== undefined)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
		return `o:{${entries.map(([k, v]) => `${JSON.stringify(k.normalize("NFC"))}:${canonicalize(v)}`).join(",")}}`;
	}
	// Functions and symbols cannot appear in normalized tool arguments; encode them
	// as an opaque marker rather than throwing, so hashing never fails closed-open.
	return "x:opaque";
}

/** SHA-256 over the complete canonical bytes. */
export function hashArguments(args: unknown): string {
	return createHash("sha256").update(canonicalize(args), "utf8").digest("hex");
}

/** Identity of the call's shape (tool + operation + resolved targets), ignoring payload. */
export function hashCanonicalCall(call: CanonicalCall): string {
	return createHash("sha256")
		.update(
			canonicalize({
				tool: call.toolName,
				operation: call.operation,
				device: call.device ?? "",
				targets: call.targets.map(t => [t.kind, t.resolved ?? "", t.dynamic]),
			}),
			"utf8",
		)
		.digest("hex");
}

// ---------------------------------------------------------------------------
// Target extraction
// ---------------------------------------------------------------------------

const PATTERN_OPERATORS = /[*?[\]{}()|]/;
const SHELL_DYNAMIC = /[$`]|\$\{|\$\(/;
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Internal URI schemes OMP resolves purely locally.
 *
 * Membership here means "reading this cannot reach the network and cannot return
 * attacker-authored content", so it is deliberately narrow. `issue://` and `pr://`
 * are NOT here: OMP's own `internal-urls/types.ts` lists them among "schemes
 * backed by network or external CLIs", and `issue-pr-protocol.ts` shells out to
 * `gh issue list`. Their content is also world-writable — anyone can file an
 * issue — which makes them one of the most attacker-reachable inputs a repo agent
 * reads. Treating them as local would skip judgment and drop the untrusted
 * provenance label at exactly the wrong moment.
 */
const LOCAL_URI_SCHEMES = new Set(["memory", "skill", "agent", "history", "artifact", "local", "rule", "omp", "xd"]);

/**
 * Schemes that leave the machine or return externally-authored content.
 *
 * `ssh://` is remote execution, not a local read. `issue://`, `pr://`, `vault://`,
 * and `mcp://` are the network/external-CLI backed internal schemes named by OMP.
 */
const REMOTE_URI_SCHEMES = new Set([
	"http",
	"https",
	"ftp",
	"ws",
	"wss",
	"ssh",
	"scp",
	"sftp",
	"git",
	"issue",
	"pr",
	"vault",
	"mcp",
]);

function schemeOf(value: string): string | undefined {
	const match = /^([a-z][a-z0-9+.-]*):/i.exec(value);
	return match?.[1]?.toLowerCase();
}

/**
 * Resolve a filesystem target against cwd.
 *
 * Returns `dynamic: true` rather than a guess whenever the value contains a glob,
 * a shell substitution, or an unexpanded variable. A scoped write whose target we
 * only guessed at must never be able to match an exact allow.
 */
export function resolvePathTarget(requested: string, cwd: string): CallTarget {
	const trimmed = requested.trim();
	if (trimmed.length === 0) {
		return { kind: "path", requested, dynamic: true };
	}
	if (PATTERN_OPERATORS.test(trimmed) || SHELL_DYNAMIC.test(trimmed) || trimmed.includes("~")) {
		return { kind: "path", requested, dynamic: true };
	}
	// `path.resolve` collapses `..` segments, so a traversal cannot escape into a
	// different resolved string than the one rules are matched against.
	return { kind: "path", requested, resolved: path.resolve(cwd, trimmed), dynamic: false };
}

/** Normalize a URL to `scheme://host/pathname`, dropping query and fragment noise. */
export function resolveUrlTarget(requested: string): CallTarget {
	if (SHELL_DYNAMIC.test(requested)) {
		return { kind: "url", requested, dynamic: true };
	}
	try {
		const url = new URL(requested);
		return {
			kind: "url",
			requested,
			resolved: `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "") || "/"}`,
			dynamic: false,
		};
	} catch {
		return { kind: "url", requested, dynamic: true };
	}
}

/**
 * Leading executable of each `;`/`&&`/`||`/`|` segment, plus literal URL operands.
 *
 * Splitting happens BEFORE tokenizing, so a separator inside quotes still yields
 * the following word as a candidate command. That over-extracts — `git commit -m
 * "a; rm"` reports `rm` the shell will never run — and the bias is deliberate:
 * a spurious candidate is noise a human can dismiss, while a missed one is a
 * bypass. This function extracts signals for the judge and for deny matching; it
 * never decides what the shell will actually do.
 */
export function extractCommandTargets(command: string): CallTarget[] {
	const targets: CallTarget[] = [];
	for (const rawSegment of command.split(/(?:\|\||&&|[;|&\n])/)) {
		const segment = rawSegment.trim();
		if (segment.length === 0) continue;
		const tokens = segment.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
		const first = tokens[0]?.replace(/^["']|["']$/g, "");
		if (!first) continue;
		targets.push({
			kind: "command",
			requested: first,
			...(SHELL_DYNAMIC.test(first) ? { dynamic: true } : { resolved: first, dynamic: false }),
		});
		for (const token of tokens.slice(1)) {
			const operand = token.replace(/^["']|["']$/g, "");
			if (operand.startsWith("-") || operand.length === 0) continue;
			if (URL_SCHEME.test(operand)) {
				targets.push(resolveUrlTarget(operand));
			}
		}
	}
	return targets;
}

/** Parse an `xd://<device>` URL into its device name. */
export function parseDeviceUrl(value: string): string | undefined {
	const match = /^xd:\/\/([^/?#\s]+)/i.exec(value.trim());
	return match?.[1];
}

interface ExtractionInput {
	toolName: string;
	args: Readonly<Record<string, unknown>>;
	cwd: string;
}

/** Field names that carry a filesystem path across the built-in and MCP tools. */
const PATH_FIELDS = ["path", "_path", "file", "filePath", "cwd", "destination", "dest", "output", "out"];
/** Field names that carry a URL. */
const URL_FIELDS = ["url", "uri", "endpoint", "href", "target"];

function readString(args: Readonly<Record<string, unknown>>, key: string): string | undefined {
	const value = args[key];
	return typeof value === "string" ? value : undefined;
}

/**
 * Extract every target a call points at, without executing or expanding anything.
 *
 * Ordering matters for readability of the audit trail but not for correctness:
 * the deny and grant matchers consider every target.
 */
export function extractTargets(input: ExtractionInput): { targets: CallTarget[]; operation: string; device?: string } {
	const { args, cwd } = input;
	const targets: CallTarget[] = [];
	let device: string | undefined;

	// `write` to an xd:// path is a nested device dispatch: the real semantics live
	// in the JSON payload, and the parent write is only a transport.
	const rawPath = readString(args, "path");
	if (rawPath) {
		const deviceName = parseDeviceUrl(rawPath);
		if (deviceName) {
			device = deviceName;
			targets.push({ kind: "device", requested: rawPath, resolved: `xd://${deviceName}`, dynamic: false });
		}
	}

	for (const field of PATH_FIELDS) {
		const value = readString(args, field);
		if (value === undefined || (field === "path" && device)) continue;
		const scheme = schemeOf(value);
		// Order matters: OMP's internal URIs (`memory://`, `skill://`, ...) are
		// scheme-shaped but resolve locally. Testing the generic URL shape first
		// would misclassify every one of them as network egress.
		if (scheme && LOCAL_URI_SCHEMES.has(scheme)) {
			targets.push({ kind: "unknown", requested: value, resolved: value, dynamic: false });
		} else if (scheme && (REMOTE_URI_SCHEMES.has(scheme) || URL_SCHEME.test(value))) {
			targets.push(resolveUrlTarget(value));
		} else {
			targets.push(resolvePathTarget(value, cwd));
		}
	}

	// `paths[]` (grep, multi-file readers) and hashline multi-file edits.
	const paths = args.paths;
	if (Array.isArray(paths)) {
		for (const entry of paths) {
			if (typeof entry === "string") targets.push(resolvePathTarget(entry, cwd));
		}
	}

	for (const field of URL_FIELDS) {
		const value = readString(args, field);
		if (value === undefined) continue;
		if (URL_SCHEME.test(value)) targets.push(resolveUrlTarget(value));
	}

	const command = readString(args, "command");
	if (command !== undefined) targets.push(...extractCommandTargets(command));

	// MCP tools carry their server and tool in the name; destination-like fields
	// are already covered above.
	if (input.toolName.startsWith("mcp__")) {
		targets.push({ kind: "mcp", requested: input.toolName, resolved: input.toolName, dynamic: false });
	}

	return { targets, operation: operationFor(input.toolName, args, device), ...(device ? { device } : {}) };
}

/** Coarse verb used for rule matching and audit rows. */
export function operationFor(toolName: string, args: Readonly<Record<string, unknown>>, device?: string): string {
	if (device) return `device:${device}`;
	const action = readString(args, "action");
	if (action) return `${toolName}:${action}`;
	const op = readString(args, "op");
	if (op) return `${toolName}:${op}`;
	return toolName;
}

// ---------------------------------------------------------------------------
// Scope classification
// ---------------------------------------------------------------------------

/** Built-in tools that are purely local reads when their targets are local. */
const LOCAL_READ_TOOLS = new Set(["read", "grep", "glob", "ast_grep", "todo", "inspect_image"]);

export interface ScopeInput {
	toolName: string;
	tier: ToolTier | undefined;
	targets: readonly CallTarget[];
	device?: string | undefined;
	/** Config-level overrides. */
	alwaysJudge: readonly string[];
	neverJudge: readonly string[];
	judgeUnknownTools: boolean;
}

/**
 * Decide whether a call may skip the judge as a purely local read.
 *
 * The default is `scoped`. A call earns `local-read` only by proving all three:
 * a read tier, a known local-read tool, and no target that can leave the machine.
 * An unknown custom or MCP tool can never prove that, so it stays scoped.
 */
export function classifyScope(input: ScopeInput): { scope: CallScope; reason: string } {
	if (input.alwaysJudge.includes(input.toolName)) {
		return { scope: "scoped", reason: "tool is listed in scope.alwaysJudge" };
	}
	// A nested device dispatch carries the mounted tool's semantics, which the
	// parent write cannot vouch for.
	if (input.device) {
		return { scope: "scoped", reason: `nested xd://${input.device} dispatch` };
	}
	if (input.tier === undefined) {
		return { scope: "scoped", reason: "tool tier could not be resolved" };
	}
	if (input.tier !== "read") {
		return { scope: "scoped", reason: `${input.tier}-tier call` };
	}

	const remote = input.targets.find(t => t.kind === "url" || (t.kind === "command" && t.dynamic));
	if (remote) {
		return { scope: "scoped", reason: `target can transmit off-machine: ${remote.requested}` };
	}

	const known = LOCAL_READ_TOOLS.has(input.toolName);
	if (!known) {
		if (input.neverJudge.includes(input.toolName)) {
			// The exemption is honored only because we already proved read tier and
			// no remote target above.
			return { scope: "local-read", reason: "tool is listed in scope.neverJudge and resolved as a local read" };
		}
		if (input.judgeUnknownTools) {
			return { scope: "scoped", reason: "unknown custom or MCP tool cannot be proven local" };
		}
		return { scope: "scoped", reason: "unknown tool" };
	}

	return { scope: "local-read", reason: "local read with no external transmission" };
}

// ---------------------------------------------------------------------------
// Sensitive content detection
// ---------------------------------------------------------------------------

/**
 * Credential-shaped literals. These are cheap, deterministic, and deliberately
 * conservative: a hit is a hard block only for reads of credential FILES, while
 * high-entropy text alone is an escalation signal so ordinary generated IDs do
 * not get blocked.
 */
const CREDENTIAL_SHAPES: ReadonlyArray<{ id: string; pattern: RegExp }> = [
	{ id: "private-key", pattern: /-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----/ },
	{ id: "openai-key", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
	{ id: "github-token", pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/ },
	{ id: "github-pat", pattern: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/ },
	{ id: "aws-access-key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
	{ id: "slack-token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
	{ id: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
	{ id: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
];

/** Path shapes that hold credentials regardless of content. */
const CREDENTIAL_PATH_SHAPES: ReadonlyArray<{ id: string; pattern: RegExp }> = [
	{ id: "dotenv", pattern: /(?:^|[/\\])\.env(?:\.[^/\\]*)?$/ },
	{ id: "ssh-dir", pattern: /(?:^|[/\\])\.ssh(?:[/\\]|$)/ },
	{ id: "aws-credentials", pattern: /(?:^|[/\\])\.aws[/\\]credentials$/ },
	{ id: "gcloud-credentials", pattern: /application_default_credentials\.json$/ },
	{ id: "npmrc", pattern: /(?:^|[/\\])\.npmrc$/ },
	{ id: "netrc", pattern: /(?:^|[/\\])\.netrc$/ },
	{ id: "pem-key", pattern: /\.(?:pem|key|p12|pfx)$/i },
	{ id: "kube-config", pattern: /(?:^|[/\\])\.kube[/\\]config$/ },
	{ id: "docker-config", pattern: /(?:^|[/\\])\.docker[/\\]config\.json$/ },
];

export interface SensitiveFinding {
	id: string;
	where: "path" | "value";
	/** Never the matched secret itself. */
	detail: string;
}

/** Scan extracted targets for credential-file shapes. */
export function scanTargets(targets: readonly CallTarget[]): SensitiveFinding[] {
	const findings: SensitiveFinding[] = [];
	for (const target of targets) {
		const candidate = target.resolved ?? target.requested;
		for (const shape of CREDENTIAL_PATH_SHAPES) {
			if (shape.pattern.test(candidate)) {
				findings.push({ id: shape.id, where: "path", detail: `${target.kind} target matches ${shape.id}` });
			}
		}
	}
	return findings;
}

/**
 * Scan raw argument values for credential literals.
 *
 * Reports the shape ID and where it was found, never the matched bytes: this
 * result is persisted and shown to humans and models.
 */
export function scanValues(args: Readonly<Record<string, unknown>>): SensitiveFinding[] {
	const findings: SensitiveFinding[] = [];
	const walk = (value: unknown, keyPath: string) => {
		if (typeof value === "string") {
			for (const shape of CREDENTIAL_SHAPES) {
				if (shape.pattern.test(value)) {
					findings.push({
						id: shape.id,
						where: "value",
						detail: `${keyPath || "<root>"} contains ${shape.id}`,
					});
				}
			}
			return;
		}
		if (Array.isArray(value)) {
			for (const [index, entry] of value.entries()) walk(entry, `${keyPath}[${index}]`);
			return;
		}
		if (value && typeof value === "object") {
			for (const [key, entry] of Object.entries(value)) {
				walk(entry, keyPath ? `${keyPath}.${key}` : key);
			}
		}
	};
	walk(args, "");
	return findings;
}

/** Shannon entropy per character, used as an escalation signal only. */
export function shannonEntropy(value: string): number {
	if (value.length === 0) return 0;
	const counts = new Map<string, number>();
	for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
	let entropy = 0;
	for (const count of counts.values()) {
		const p = count / value.length;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/** A rule target is exact only when it contains no pattern operator at all. */
export function isExactTarget(target: string): boolean {
	return !PATTERN_OPERATORS.test(target) && !target.startsWith("re:");
}

/**
 * A judge suggestion may mint an exact allow only when it is fully specified.
 *
 * One wildcard is enough to disqualify it. This is checked here as well as in the
 * judge parser so a suggestion arriving from persistence cannot bypass the rule.
 */
export function isExactSuggestion(suggestion: RuleSuggestion): boolean {
	return suggestion.kind !== "allow-exact" || isExactTarget(suggestion.target);
}

/** Compile a rule target to a matcher. `re:` prefix is a regex; otherwise a glob. */
export function compileTarget(target: string): (candidate: string) => boolean {
	if (target.startsWith("re:")) {
		const source = target.slice(3);
		let regex: RegExp;
		try {
			regex = new RegExp(source);
		} catch {
			// An uncompilable rule must not silently match nothing on a deny; treat it
			// as matching nothing but surface it through validation elsewhere.
			return () => false;
		}
		return candidate => regex.test(candidate);
	}
	if (!PATTERN_OPERATORS.test(target)) {
		return candidate => candidate === target;
	}
	// Minimal glob: `**` crosses separators, `*` does not, `?` is one character.
	// `**` is parked on a placeholder that cannot appear in an escaped target — the
	// escape above backslash-escapes `\`, so a literal `\x00` in the input is
	// already `\\x00` and cannot collide with this sentinel.
	const doubleStar = "\\x00DOUBLESTAR\\x00";
	const escaped = target.replace(/[.+^${}()|\\]/g, "\\$&");
	const source = `^${escaped
		.replaceAll("**", doubleStar)
		.replace(/\*/g, "[^/]*")
		.replaceAll(doubleStar, ".*")
		.replace(/\?/g, "[^/]")}$`;
	const regex = new RegExp(source);
	return candidate => regex.test(candidate);
}

export interface RuleMatch {
	rule: PolicyRule;
	target: CallTarget;
}

/**
 * Highest-specificity matching deny rule, or `undefined`.
 *
 * A deny may match a dynamic target: refusing to run something we cannot pin down
 * is safe, whereas allowing one is not.
 */
export function matchDeny(
	rules: readonly PolicyRule[],
	toolName: string,
	operation: string,
	targets: readonly CallTarget[],
): RuleMatch | undefined {
	let best: RuleMatch | undefined;
	for (const rule of rules) {
		if (rule.kind !== "deny-exact" && rule.kind !== "deny-pattern") continue;
		if (rule.toolName !== "*" && rule.toolName !== toolName) continue;
		if (rule.operation && rule.operation !== operation) continue;
		const matches = compileTarget(rule.target);
		for (const target of targets) {
			const candidates = [target.requested, target.resolved].filter((v): v is string => typeof v === "string");
			if (!candidates.some(matches)) continue;
			if (!best || rule.specificity > best.rule.specificity) best = { rule, target };
			break;
		}
	}
	return best;
}

/**
 * The one config rule that may skip the judge, or `undefined`.
 *
 * Fact 35 permits a judge bypass only for a "fully specified canonical allow with
 * no wildcard, regex, capture, or omitted argument", and fact 32 requires the
 * grant to carry working-directory identity. Both are enforced here:
 *
 * - `argumentsHash` must pin the literal call. A rule naming tool and target
 *   still omits every other argument — a `write` rule naming a path alone would
 *   authorize arbitrary content at that path.
 * - `target` must match a RESOLVED, non-dynamic target of this call. The
 *   arguments hash alone is cwd-blind: `write {path: "src/a.ts"}` hashes
 *   identically in every repository, so a user-scoped pinned rule would fire
 *   everywhere. Matching the resolved absolute path binds it to one location.
 *
 * Anything less is posture, surfaced by {@link collectPostureHints}.
 */
export function matchExactAllow(
	rules: readonly PolicyRule[],
	toolName: string,
	argumentsHash: string,
	targets: readonly CallTarget[],
	cwd: string,
): PolicyRule | undefined {
	// An unresolved target cannot be bound to a location, so it can never match.
	const resolved = targets.filter(t => !t.dynamic && t.resolved !== undefined).map(t => t.resolved);
	for (const rule of rules) {
		if (rule.kind !== "allow-exact") continue;
		// A wildcard tool would make the rule broad by definition.
		if (rule.toolName !== toolName) continue;
		if (!isExactTarget(rule.target)) continue;
		if (rule.argumentsHash === undefined) continue;
		if (rule.argumentsHash !== argumentsHash) continue;
		// Location identity. Without it the same hash authorizes the call in every
		// checkout — `bash {command: "scripts/x.sh"}` hashes identically everywhere,
		// and for a command target `resolved` is the executable exactly as typed, so
		// the target check alone does not bind a location.
		if (rule.cwd === undefined || path.resolve(rule.cwd) !== path.resolve(cwd)) continue;
		if (!resolved.includes(rule.target)) continue;
		return rule;
	}
	return undefined;
}

/**
 * Non-binding hints for the judge's posture.
 *
 * Includes every allow that did NOT qualify as a judge bypass, so the judge can
 * see that an operator expressed intent here without that intent becoming
 * authority.
 */
export function collectPostureHints(
	rules: readonly PolicyRule[],
	toolName: string,
	targets: readonly CallTarget[],
): string[] {
	const hints: string[] = [];
	for (const rule of rules) {
		const relevant = rule.kind === "allow-pattern" || rule.kind === "posture" || rule.kind === "allow-exact";
		if (!relevant) continue;
		if (rule.toolName !== "*" && rule.toolName !== toolName) continue;
		const matches = compileTarget(rule.target);
		const hit = targets.some(target =>
			[target.requested, target.resolved].filter((v): v is string => typeof v === "string").some(matches),
		);
		if (!hit) continue;
		if (rule.kind === "posture") {
			hints.push(`posture ${rule.id}: sensitivity ${rule.sensitivity ?? "unchanged"} — ${rule.reason}`);
		} else if (rule.kind === "allow-pattern") {
			hints.push(`allow-pattern ${rule.id} matches, but a patterned allow never skips judgment — ${rule.reason}`);
		} else {
			// An allow-exact that reached here failed to qualify as a bypass.
			hints.push(
				`allow-exact ${rule.id} matches this target but does not pin the exact call ` +
					`(no argumentsHash), so it is advisory only — ${rule.reason}`,
			);
		}
	}
	return hints;
}

/**
 * Is this call a write or edit against a protected policy surface?
 *
 * Three spellings of the same file must all trip the floor:
 *
 * 1. the resolved absolute path (`path.resolve` collapses `..`);
 * 2. a symlink pointing at a protected file — resolved with `realpathSync`,
 *    because `path.resolve` does not follow links, and a writable symlink beside
 *    a protected config is otherwise a clean walk through the deny floor;
 * 3. a dynamic target whose literal text names a protected path (`~/...`,
 *    `$HOME/...`), matched by suffix since it cannot be resolved.
 *
 * Symlink resolution is also applied to the *parent* directory, so a link like
 * `evil/ -> .omp/` cannot launder a write to `evil/smart-approve.yml`.
 */
export function matchProtected(
	protectedTargets: readonly string[],
	targets: readonly CallTarget[],
	tier: ToolTier | undefined,
): CallTarget | undefined {
	if (tier === "read") return undefined;
	const protectedSet = new Set(protectedTargets);
	for (const target of targets) {
		if (target.kind !== "path" && target.kind !== "unknown") continue;
		if (target.resolved) {
			if (protectedSet.has(target.resolved)) return target;
			for (const candidate of realpathCandidates(target.resolved)) {
				if (protectedSet.has(candidate)) return target;
			}
			continue;
		}
		// A dynamic target cannot be resolved, so compare its literal text against
		// the protected list by suffix — enough to catch `~`- and variable-prefixed
		// spellings of a protected file.
		const requested = target.requested.replace(/^~/, "");
		if (requested.length > 1 && protectedTargets.some(p => p.endsWith(requested))) return target;
	}
	return undefined;
}

/**
 * Every real path this target could actually write to.
 *
 * Resolves the file itself when it exists, and separately resolves its parent
 * directory so a link in the path prefix is caught even when the leaf does not
 * exist yet — which is the normal case for a create-then-overwrite attack.
 */
function realpathCandidates(resolved: string): string[] {
	const candidates: string[] = [];
	try {
		if (existsSync(resolved)) candidates.push(realpathSync(resolved));
	} catch {
		// Unreadable path: the literal resolved form above already covers it.
	}
	try {
		const parent = path.dirname(resolved);
		if (existsSync(parent)) candidates.push(path.join(realpathSync(parent), path.basename(resolved)));
	} catch {
		// Same rationale.
	}
	return candidates;
}

// ---------------------------------------------------------------------------
// Deterministic precedence
// ---------------------------------------------------------------------------

export type DeterministicOutcome =
	| {
			kind: "block";
			stage: "protected-policy" | "deny-rule" | "sensitive-read";
			risk: RiskClass;
			reason: string;
			ruleId?: string;
	  }
	| { kind: "allow"; stage: "local-read"; reason: string }
	| { kind: "judge"; reason: string; postureHints: string[] };

export interface DeterministicInput {
	toolName: string;
	operation: string;
	tier: ToolTier | undefined;
	targets: readonly CallTarget[];
	device?: string | undefined;
	rawArguments: Readonly<Record<string, unknown>>;
	rules: readonly PolicyRule[];
	protectedTargets: readonly string[];
	alwaysJudge: readonly string[];
	neverJudge: readonly string[];
	judgeUnknownTools: boolean;
}

/**
 * Run the deterministic ladder.
 *
 * Order is fixed and load-bearing:
 *
 *   protected-policy write  -> block
 *   matching deny rule      -> block
 *   credential-file read    -> block
 *   safe unscoped local read-> allow
 *   otherwise               -> judge
 *
 * Exact grant matching deliberately lives in the gate, not here: it needs the
 * store and the policy hash, and it must run after these blocks so a grant can
 * never override a deny.
 */
export function evaluateDeterministic(input: DeterministicInput): DeterministicOutcome {
	const protectedHit = matchProtected(input.protectedTargets, input.targets, input.tier);
	if (protectedHit) {
		return {
			kind: "block",
			stage: "protected-policy",
			risk: "safety-tampering",
			reason:
				`This call would modify an active safety-policy file (${protectedHit.requested}). ` +
				`Smart Approve protects its own configuration and OMP's approval settings by default. ` +
				`A human can override this deliberately with /smart-approve override.`,
		};
	}

	const deny = matchDeny(input.rules, input.toolName, input.operation, input.targets);
	if (deny) {
		return {
			kind: "block",
			stage: "deny-rule",
			risk: deny.rule.risk ?? "policy-violation",
			reason: `Blocked by deny rule "${deny.rule.id}": ${deny.rule.reason} (target: ${deny.target.requested})`,
			ruleId: deny.rule.id,
		};
	}

	const pathFindings = scanTargets(input.targets);
	if (pathFindings.length > 0) {
		const first = pathFindings[0];
		return {
			kind: "block",
			stage: "sensitive-read",
			risk: "exfiltration",
			reason:
				`This call targets credential material (${first?.detail ?? "credential file"}). ` +
				`Add an explicit allow rule if this is genuinely required.`,
		};
	}

	const scope = classifyScope({
		toolName: input.toolName,
		tier: input.tier,
		targets: input.targets,
		device: input.device,
		alwaysJudge: input.alwaysJudge,
		neverJudge: input.neverJudge,
		judgeUnknownTools: input.judgeUnknownTools,
	});

	if (scope.scope === "local-read") {
		return { kind: "allow", stage: "local-read", reason: scope.reason };
	}

	return {
		kind: "judge",
		reason: scope.reason,
		postureHints: collectPostureHints(input.rules, input.toolName, input.targets),
	};
}

// ---------------------------------------------------------------------------
// Retry families
// ---------------------------------------------------------------------------

/**
 * Deterministic key grouping materially equivalent retries.
 *
 * Deliberately excludes the arguments hash: an agent that retries the same
 * destructive operation with cosmetically different arguments must land in the
 * same family, or the loop breaker never fires.
 */
export function retryFamilyKey(input: {
	sourceAgentId: string;
	toolName: string;
	operation: string;
	targets: readonly CallTarget[];
	risk: RiskClass;
}): string {
	const destination = input.targets
		.map(t => `${t.kind}:${t.resolved ?? t.requested}`)
		.sort()
		.join("|");
	return createHash("sha256")
		.update(
			canonicalize([input.sourceAgentId, input.toolName, input.operation, destination, riskFamily(input.risk)]),
			"utf8",
		)
		.digest("hex")
		.slice(0, 32);
}

/** Collapse near-equivalent risks so a retry cannot escape by re-classifying. */
export function riskFamily(risk: RiskClass): string {
	switch (risk) {
		case "prompt-injection":
		case "exfiltration":
			return "untrusted-egress";
		case "destructive-action":
		case "wrong-target":
			return "destructive";
		case "safety-tampering":
		case "policy-violation":
			return "policy";
		default:
			return "uncertain";
	}
}
