/**
 * Judge-facing context assembly.
 *
 * Three concerns live here, in dependency order:
 *
 *  1. {@link Redactor} — a thin, non-mutating wrapper over OMP's own
 *     `SecretObfuscator`. Smart Approve never invents its own redaction; it
 *     reuses the host's secret machinery so placeholders stay stable and
 *     reversible on the host side.
 *  2. A deterministic metadata minimizer that strips operator identity and tool
 *     plumbing, so the same call always produces byte-identical evidence.
 *  3. {@link ProvenanceTracker} and {@link buildJudgeInput}, which turn live
 *     session activity into a bounded, fully redacted judge snapshot.
 *
 * Nothing here ever retains a raw tool-result body, and nothing here can carry a
 * previous judgment forward: {@link JudgeInput} has no field a prompt, a hidden
 * rationale, or a verdict could hide in.
 */

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import os from "node:os";
import {
	builtinCredentialSecretEntries,
	collectEnvSecrets,
	getSecretPlaceholderKeySync,
	loadSecrets,
	type SecretEntry,
} from "@oh-my-pi/pi-coding-agent/secrets";
import { obfuscateToolArguments, SecretObfuscator } from "@oh-my-pi/pi-coding-agent/secrets/obfuscator";
import type { CallTarget, JudgeInput, ProvenanceEntry, ProvenanceSource, SensitivityLevel } from "./contracts.ts";

// ---------------------------------------------------------------------------
// Inert-data delimiters
// ---------------------------------------------------------------------------

/**
 * The single word both delimiters are built from. Neutralizing this one token
 * kills every forgeable variant of the fence in one pass.
 */
export const EVIDENCE_TOKEN = "UNTRUSTED_EVIDENCE";
export const EVIDENCE_OPEN = `<<<${EVIDENCE_TOKEN}`;
export const EVIDENCE_CLOSE = `${EVIDENCE_TOKEN}>>>`;

/** Defang a fence forged inside content so quoted text cannot close its own block. */
export function neutralizeEvidenceMarkers(text: string): string {
	return text.replaceAll(EVIDENCE_TOKEN, "UNTRUSTED-EVIDENCE");
}

/** Fence a block of tool-provided text as inert data. */
export function wrapEvidence(text: string): string {
	return `${EVIDENCE_OPEN}\n${neutralizeEvidenceMarkers(text)}\n${EVIDENCE_CLOSE}`;
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

export interface Redactor {
	/** Deep-clone then obfuscate. MUST NOT mutate the input. */
	redactArguments(args: Record<string, unknown>): Record<string, unknown>;
	redactText(text: string): string;
	hasSecrets(): boolean;
}

export function createRedactor(entries: SecretEntry[], key: string | (() => string)): Redactor {
	const obfuscator = new SecretObfuscator(entries, key);
	return {
		redactArguments(args) {
			// `obfuscateToolArguments` hands the caller's own object straight back when
			// no secrets are configured, so cloning FIRST is what actually guarantees
			// the live tool arguments are unreachable from the judge payload — not just
			// unmutated, but a different object entirely.
			return obfuscateToolArguments(obfuscator, structuredClone(args));
		},
		redactText(text) {
			return obfuscator.obfuscate(text);
		},
		hasSecrets() {
			return obfuscator.hasSecrets();
		},
	};
}

/**
 * Build the session redactor from the same three sources OMP itself uses, in
 * precedence order: environment values, then user/project `secrets.yml`, then
 * built-in credential shapes. User-configured entries are registered ahead of
 * the built-ins so a named secret keeps its friendly placeholder.
 *
 * The placeholder key is resolved lazily: a session that never redacts anything
 * never touches (or creates) the key file.
 */
export async function loadSessionRedactor(cwd: string, agentDir: string): Promise<Redactor> {
	const entries: SecretEntry[] = [
		...collectEnvSecrets(),
		...(await loadSecrets(cwd, agentDir)),
		...builtinCredentialSecretEntries(),
	];
	return createRedactor(entries, () => getSecretPlaceholderKeySync(agentDir));
}

// ---------------------------------------------------------------------------
// Deterministic metadata minimizer
// ---------------------------------------------------------------------------

/**
 * Keys carrying per-run identity or tool plumbing rather than call semantics.
 * Looked up after {@link normalizeKey}, so `audit_id`, `auditId`, and `AuditID`
 * all collapse onto one entry. Compared with `=== true` so an inherited
 * `Object.prototype` member can never read as a hit.
 */
const DROPPED_METADATA_KEYS: Record<string, true> = {
	additionalproperties: true,
	auditid: true,
	callid: true,
	correlationid: true,
	idempotencykey: true,
	inputschema: true,
	jsonschema: true,
	messageid: true,
	meta: true,
	nonce: true,
	outputschema: true,
	parametersschema: true,
	requestid: true,
	runid: true,
	schema: true,
	sessionid: true,
	spanid: true,
	toolcallid: true,
	traceid: true,
};

/** Deep enough for real tool arguments; also the cycle guard for in-process callers. */
const MAX_MINIMIZE_DEPTH = 32;

/** Fold `_path`, `audit_id`, and `$schema` onto one comparable spelling. */
function normalizeKey(key: string): string {
	return key.replace(/[$_-]/g, "").toLowerCase();
}

/**
 * Replace the operator's home directory with `~`. The absolute prefix identifies
 * the machine and the human, never the action, and sending it would make the
 * same logical call produce different evidence on different hosts.
 */
export function minimizeText(text: string): string {
	const home = os.homedir();
	return home.length > 1 ? text.replaceAll(home, "~") : text;
}

function minimizeValue(value: unknown, home: string | undefined, depth: number): unknown {
	if (depth > MAX_MINIMIZE_DEPTH) return null;
	if (typeof value === "string") return home === undefined ? value : value.replaceAll(home, "~");
	if (Array.isArray(value)) return value.map(item => minimizeValue(item, home, depth + 1));
	if (typeof value === "object" && value !== null) return minimizeRecord(value, home, depth + 1);
	return value;
}

function minimizeRecord(record: object, home: string | undefined, depth: number): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(record)) {
		if (DROPPED_METADATA_KEYS[normalizeKey(key)] === true) continue;
		const minimized = minimizeValue(value, home, depth);
		// `JSON.parse` gives `__proto__` as a real own property, so model-authored
		// arguments can carry one. Plain assignment would hit the inherited setter
		// and silently drop it — which is exactly how you would hide a field from
		// the judge. Define it instead.
		if (key === "__proto__") {
			Object.defineProperty(out, key, { value: minimized, enumerable: true, writable: true, configurable: true });
			continue;
		}
		out[key] = minimized;
	}
	return out;
}

/**
 * The second pass after secret redaction. Purely deterministic: identical input
 * yields byte-identical output within a process, and across processes for every
 * host sharing the same home path.
 */
export function minimizeMetadata(args: Record<string, unknown>): Record<string, unknown> {
	const home = os.homedir();
	return minimizeRecord(args, home.length > 1 ? home : undefined, 0);
}

// ---------------------------------------------------------------------------
// Shape detection
// ---------------------------------------------------------------------------

/**
 * Non-global: safe for repeated `.test` because there is no `lastIndex` to carry.
 * The scheme is length-bounded so scanning a multi-megabyte payload with no `://`
 * stays linear instead of degenerating into a per-position greedy backtrack.
 */
const URL_SHAPE = /[a-z][a-z0-9+.-]{0,15}:\/\/[^\s"'<>\\]+/i;

/**
 * Credential-shaped fragments. By the time the judge reads them these are
 * already placeholders, so preserving the shape is what tells the judge a
 * credential was present at all — the first pattern matches OMP's own
 * placeholder so a redacted secret is never sampled away.
 */
const CREDENTIAL_SHAPES: readonly RegExp[] = [
	/\$\$(?:[A-Z0-9]+_)?[A-Z0-9]{4,}(?::[ULCM])?\$\$/,
	/\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}/,
	/\bglpat-[A-Za-z0-9_-]{16,}/,
	/\bsk-[A-Za-z0-9_-]{16,}/,
	/\bxox[abprs]-[A-Za-z0-9-]{10,}/,
	/\bAKIA[0-9A-Z]{16}\b/,
	/-----BEGIN [A-Z ]*PRIVATE KEY-----/,
	/\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
	// Anchored on the keyword, never on a leading `[A-Za-z0-9_-]*` run: that prefix
	// would make every position in a long token a fresh backtracking start.
	/(?:secret|token|password|api[_-]?key)[A-Za-z0-9_-]*\s*[=:]\s*\S{8,}/i,
];

/**
 * Global twins of the shapes above, used only through `matchAll`, which reads
 * `lastIndex` from a fresh clone and therefore stays stateless across calls.
 */
const SALIENT_SCANS: readonly RegExp[] = [URL_SHAPE, ...CREDENTIAL_SHAPES].map(
	shape => new RegExp(shape.source, `${shape.flags}g`),
);

function hasCredentialShape(text: string): boolean {
	for (const shape of CREDENTIAL_SHAPES) {
		if (shape.test(text)) return true;
	}
	return false;
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

const DEFAULT_RING_SIZE = 40;
/** One provenance line. Long enough to be informative, short enough to be inert. */
const SUMMARY_CHAR_LIMIT = 200;
/** Intent and rationale get more room; they are the reference the judge compares against. */
const MESSAGE_CHAR_LIMIT = 2000;

/** Tool name -> provenance source, for the tools whose source is knowable by name. */
const SOURCE_BY_TOOL: Record<string, ProvenanceSource> = {
	agent: "subagent",
	browser: "browser",
	chrome: "browser",
	curl: "external-network",
	dispatch_agent: "subagent",
	fetch: "external-network",
	glob: "local",
	grep: "local",
	list: "local",
	ls: "local",
	playwright: "browser",
	read: "local",
	task: "subagent",
	tree: "local",
	web_fetch: "external-network",
	web_search: "external-network",
	webfetch: "external-network",
	websearch: "external-network",
};

/**
 * Classify where a tool result came from. Known local reads stay `local` even
 * when their content mentions a URL — reading a file that quotes a link is not
 * a network fetch — while an unrecognized tool whose output carries a URL is
 * treated as network-reachable.
 */
export function classifyProvenance(toolName: string, summary: string): ProvenanceSource {
	const name = toolName.toLowerCase();
	if (name.startsWith("mcp__")) return "mcp";
	const known = SOURCE_BY_TOOL[name];
	if (known !== undefined) return known;
	return URL_SHAPE.test(summary) ? "external-network" : "local";
}

function clampText(text: string, limit: number): string {
	return text.length <= limit ? text : `${text.slice(0, limit - 1)}…`;
}

function oneLine(text: string, limit: number): string {
	return clampText(text.replace(/\s+/g, " ").trim(), limit);
}

export interface ProvenanceTracker {
	recordUserMessage(text: string): void;
	recordAssistantRationale(text: string): void;
	recordToolResult(input: { toolName: string; isError: boolean; summary: string; at: number }): void;
	latestUserIntent(): string;
	latestAssistantRationale(): string;
	recent(limit: number): ProvenanceEntry[];
	clear(): void;
}

/**
 * A bounded in-memory ring of what the session just did. Raw bodies never enter
 * it: every entry is redacted, whitespace-collapsed, and capped, so the ring is
 * safe to read into a prompt and worthless to an attacker who wants a payload
 * echoed back verbatim.
 */
export function createProvenanceTracker(options: { redactor: Redactor; ringSize?: number }): ProvenanceTracker {
	const redactor = options.redactor;
	const ringSize = Math.max(1, options.ringSize ?? DEFAULT_RING_SIZE);
	const ring: ProvenanceEntry[] = [];
	let userIntent = "";
	let agentRationale = "";

	function push(entry: ProvenanceEntry): void {
		ring.push(entry);
		if (ring.length > ringSize) ring.splice(0, ring.length - ringSize);
	}

	return {
		recordUserMessage(text) {
			userIntent = clampText(minimizeText(redactor.redactText(text)), MESSAGE_CHAR_LIMIT);
			push({
				source: "user",
				toolName: "user",
				summary: oneLine(userIntent, SUMMARY_CHAR_LIMIT),
				at: Date.now(),
				untrusted: false,
			});
		},

		recordAssistantRationale(text) {
			agentRationale = clampText(minimizeText(redactor.redactText(text)), MESSAGE_CHAR_LIMIT);
			push({
				source: "assistant",
				toolName: "assistant",
				summary: oneLine(agentRationale, SUMMARY_CHAR_LIMIT),
				at: Date.now(),
				untrusted: false,
			});
		},

		recordToolResult(input) {
			const body = input.isError ? `error: ${input.summary}` : input.summary;
			const summary = oneLine(minimizeText(redactor.redactText(body)), SUMMARY_CHAR_LIMIT);
			push({
				source: classifyProvenance(input.toolName, summary),
				toolName: input.toolName,
				summary,
				at: input.at,
				// Tool output sits outside the user/assistant trust boundary by construction.
				untrusted: true,
			});
		},

		latestUserIntent() {
			return userIntent;
		},

		latestAssistantRationale() {
			return agentRationale;
		},

		recent(limit) {
			if (limit <= 0) return [];
			return ring.slice(Math.max(0, ring.length - limit));
		},

		clear() {
			ring.length = 0;
			userIntent = "";
			agentRationale = "";
		},
	};
}

// ---------------------------------------------------------------------------
// Argument view
// ---------------------------------------------------------------------------

export interface ArgumentsView {
	text: string;
	incompleteCriticalContext: boolean;
}

const HEAD_CHARS = 400;
const TAIL_CHARS = 400;
/** Below this a truncation descriptor costs more than the value it replaces. */
const MIN_FIELD_BUDGET = HEAD_CHARS + TAIL_CHARS + 256;
/** Even a preserved field is capped, so a hostile 10 MB `command` cannot flood the judge. */
const MAX_PRESERVED_FIELD_BYTES = 65_536;
const MAX_PRESERVED_FRAGMENTS = 24;
const MAX_FRAGMENT_CHARS = 512;

/**
 * Field names whose value decides what the call actually touches. Sampling one
 * of these could change the judge's answer, so they are never sampled.
 * Looked up after {@link normalizeKey}, which folds `_path` onto `path`.
 */
const PRESERVED_FIELD_NAMES: Record<string, true> = {
	command: true,
	cwd: true,
	destination: true,
	env: true,
	host: true,
	path: true,
	paths: true,
	to: true,
	url: true,
};

/**
 * Field names that describe a call without being able to change what it does.
 * Truncating one is not a critical omission. Truncating anything else —
 * `content`, `code`, `input`, `patch`, `body`, `payload`, `args`, or any name we
 * do not recognize — is, because it might have carried the real action.
 */
const COSMETIC_FIELD_NAMES: Record<string, true> = {
	changelog: true,
	comment: true,
	description: true,
	docstring: true,
	explanation: true,
	i: true,
	intent: true,
	label: true,
	note: true,
	notes: true,
	rationale: true,
	reason: true,
	summary: true,
	title: true,
};

/** Text the judge sees for one field. Strings stay raw so head/tail read cleanly. */
function serializeField(value: unknown): string {
	if (typeof value === "string") return value;
	if (value === undefined) return "null";
	return JSON.stringify(value);
}

/** True when the field's name or its content decides the call's target. */
function isPreservedField(key: string, value: unknown): boolean {
	if (PRESERVED_FIELD_NAMES[normalizeKey(key)] === true) return true;
	if (typeof value !== "string") return false;
	return URL.canParse(value) || hasCredentialShape(value);
}

/**
 * Pull URLs and credential shapes out of a value that is about to be sampled.
 * An exfiltration target parked three megabytes into a payload is precisely what
 * a head/tail window would miss, and precisely what the judge must see.
 */
function extractSalientFragments(text: string): string[] {
	const found = new Set<string>();
	for (const scan of SALIENT_SCANS) {
		for (const match of text.matchAll(scan)) {
			found.add(clampText(match[0], MAX_FRAGMENT_CHARS));
			if (found.size >= MAX_PRESERVED_FRAGMENTS) return [...found];
		}
	}
	return [...found];
}

function describeTruncation(serialized: string, bytes: number): Record<string, unknown> {
	const fragments = extractSalientFragments(serialized);
	return {
		__truncated: true,
		bytes,
		// Over the COMPLETE value, never the sample: this hash is what lets a later
		// audit or scanner prove which bytes the judge was shown a slice of.
		sha256: createHash("sha256").update(serialized, "utf8").digest("hex"),
		head: serialized.slice(0, HEAD_CHARS),
		tail: serialized.slice(Math.max(HEAD_CHARS, serialized.length - TAIL_CHARS)),
		...(fragments.length === 0 ? {} : { preserved: fragments }),
	};
}

/**
 * Redact, minimize, and size-bound the arguments. Under `threshold` the judge
 * sees the whole thing; over it, each oversized top-level field collapses to a
 * head/tail/size/hash descriptor plus the salient fragments found anywhere
 * inside it.
 */
export function buildArgumentsView(
	args: Record<string, unknown>,
	threshold: number,
	redactor: Redactor,
): ArgumentsView {
	const minimized = minimizeMetadata(redactor.redactArguments(args));
	const whole = JSON.stringify(minimized, null, 2);
	if (Buffer.byteLength(whole, "utf8") <= threshold) return { text: whole, incompleteCriticalContext: false };

	const budget = Math.max(MIN_FIELD_BUDGET, Math.floor(threshold / 2));
	const summary: Record<string, unknown> = {};
	let incompleteCriticalContext = false;
	for (const [key, value] of Object.entries(minimized)) {
		const serialized = serializeField(value);
		const bytes = Buffer.byteLength(serialized, "utf8");
		if (bytes <= (isPreservedField(key, value) ? MAX_PRESERVED_FIELD_BYTES : budget)) {
			summary[key] = value;
			continue;
		}
		summary[key] = describeTruncation(serialized, bytes);
		if (COSMETIC_FIELD_NAMES[normalizeKey(key)] !== true) incompleteCriticalContext = true;
	}
	return { text: JSON.stringify(summary, null, 2), incompleteCriticalContext };
}

// ---------------------------------------------------------------------------
// Judge input
// ---------------------------------------------------------------------------

/** How much of the provenance ring the judge sees. Bounded for tokens and latency. */
const RECENT_ACTION_LIMIT = 12;

export interface BuildJudgeInputOptions {
	toolName: string;
	operation: string;
	targets: readonly CallTarget[];
	sourceAgentId: string;
	rawArguments: Readonly<Record<string, unknown>>;
	threshold: number;
	redactor: Redactor;
	tracker: ProvenanceTracker;
	policyDocuments: readonly string[];
	postureHints: readonly string[];
	sensitivity: SensitivityLevel;
}

/**
 * Assemble one judge snapshot from overlapping primary-session evidence.
 *
 * Every field is derived from current session state. There is deliberately no
 * channel for a previous judge prompt, hidden judge reasoning, or an earlier
 * verdict: the tracker never holds them and {@link JudgeInput} has nowhere to
 * put them, so one judgment cannot be steered by the judgment before it.
 */
export function buildJudgeInput(input: BuildJudgeInputOptions): JudgeInput {
	const view = buildArgumentsView(input.rawArguments, input.threshold, input.redactor);
	return {
		// The user is the authority the judge measures the call against, so intent is
		// not fenced as untrusted evidence — only defanged against fence forgery.
		userIntent: neutralizeEvidenceMarkers(input.tracker.latestUserIntent()),
		agentRationale: wrapEvidence(input.tracker.latestAssistantRationale()),
		toolName: input.toolName,
		operation: input.operation,
		argumentsView: wrapEvidence(view.text),
		targets: input.targets.map(target => ({
			...target,
			requested: minimizeText(input.redactor.redactText(target.requested)),
			...(target.resolved === undefined
				? {}
				: { resolved: minimizeText(input.redactor.redactText(target.resolved)) }),
		})),
		sourceAgentId: input.sourceAgentId,
		recentActions: input.tracker.recent(RECENT_ACTION_LIMIT).map(entry => ({
			...entry,
			// Fenced inline: a provenance summary is single-line by contract.
			summary: `${EVIDENCE_OPEN} ${neutralizeEvidenceMarkers(entry.summary)} ${EVIDENCE_CLOSE}`,
		})),
		policyDocuments: [...input.policyDocuments],
		postureHints: [...input.postureHints],
		sensitivity: input.sensitivity,
		incompleteCriticalContext: view.incompleteCriticalContext,
	};
}
