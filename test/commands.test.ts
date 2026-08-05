import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { holdCall, registerEndpoint, resetBrokerForTests } from "../src/broker.ts";
import {
	type CommandDeps,
	clearSuggestions,
	createCommands,
	GRANT_SCOPE_OPTIONS,
	OVERRIDE_APPROVE,
	OVERRIDE_DENY,
	OVERRIDE_EXPIRE,
	recordSuggestion,
	SUBCOMMANDS,
} from "../src/commands.ts";
import { type ResolvedConfig, resolveConfig, smartApproveConfigSchema } from "../src/config.ts";
import type { AuditRecord, CallTarget, FrozenCall, Grant, PendingApproval, PolicyRule } from "../src/contracts.ts";
import { hashArguments, matchExactAllow } from "../src/policy.ts";
import { openStore, type SmartApproveStore } from "../src/store.ts";
import { formatDuration, STATUS_KEY, type UiHost, WIDGET_BYPASS, WIDGET_OVERRIDE } from "../src/ui.ts";

const NOW = 1_700_000_000_000;
/** Deterministic so a test can queue a matching (or deliberately wrong) answer. */
const CHALLENGE = "type-me-42";
const SECRET_CONTENT = "root::0:0:::";

const ARGS: Record<string, unknown> = { path: "/etc/shadow", content: SECRET_CONTENT };
const ARGS_HASH = hashArguments(ARGS);

// ---------------------------------------------------------------------------
// Fake UI
// ---------------------------------------------------------------------------

interface FakeUi {
	ui: UiHost;
	selects: Array<{
		title: string;
		options: Array<{ label: string; description?: string }>;
		/** Widget bodies live on screen when the question was asked, keyed by widget. */
		onScreen: Record<string, string[]>;
	}>;
	confirms: Array<{ title: string; message: string }>;
	inputs: Array<{ title: string; placeholder: string | undefined }>;
	notices: Array<{ message: string; type: string | undefined }>;
	widgets: Array<{ key: string; lines: string[] | undefined }>;
	statuses: Array<{ key: string; text: string | undefined }>;
}

interface UiScript {
	hasUI?: boolean;
	/** Answers consumed in order; an exhausted queue answers `undefined`/`false`. */
	selects?: Array<string | undefined>;
	inputs?: Array<string | undefined>;
	confirms?: boolean[];
	/** Runs when a select dialog is asked, so a test can throw or change state mid-command. */
	onSelect?: () => void;
	/** Runs when a confirm dialog is answered, so a test can change state mid-command. */
	onConfirm?: () => void;
}

function createFakeUi(script: UiScript = {}): FakeUi {
	const selects: FakeUi["selects"] = [];
	const confirms: FakeUi["confirms"] = [];
	const inputs: FakeUi["inputs"] = [];
	const notices: FakeUi["notices"] = [];
	const widgets: FakeUi["widgets"] = [];
	const statuses: FakeUi["statuses"] = [];
	const selectQueue = [...(script.selects ?? [])];
	const inputQueue = [...(script.inputs ?? [])];
	const confirmQueue = [...(script.confirms ?? [])];
	const ui: UiHost = {
		hasUI: script.hasUI ?? true,
		select: async (title, options) => {
			const onScreen: Record<string, string[]> = {};
			for (const written of widgets) {
				if (written.lines === undefined) delete onScreen[written.key];
				else onScreen[written.key] = written.lines;
			}
			selects.push({ title, options, onScreen });
			script.onSelect?.();
			return selectQueue.length === 0 ? undefined : selectQueue.shift();
		},
		confirm: async (title, message) => {
			confirms.push({ title, message });
			script.onConfirm?.();
			return confirmQueue.length === 0 ? false : (confirmQueue.shift() ?? false);
		},
		input: async (title, placeholder) => {
			inputs.push({ title, placeholder });
			return inputQueue.length === 0 ? undefined : inputQueue.shift();
		},
		notify: (message, type) => {
			notices.push({ message, type });
		},
		setStatus: (key, text) => {
			statuses.push({ key, text });
		},
		setWidget: (key, lines) => {
			widgets.push({ key, lines });
		},
	};
	return { ui, selects, confirms, inputs, notices, widgets, statuses };
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let root: string;
let store: SmartApproveStore;
let resolved: ResolvedConfig;
let clock: number;

beforeEach(() => {
	resetBrokerForTests();
	clearSuggestions();
	clock = NOW;
	root = mkdtempSync(path.join(os.tmpdir(), "smart-approve-commands-"));
	resolved = resolveConfig([], [], {
		cwd: path.join(root, "project"),
		agentDir: path.join(root, "agent"),
		home: root,
	});
	store = openStore(path.join(root, "state", "state.sqlite"));
});

afterEach(() => {
	store.close();
	rmSync(root, { recursive: true, force: true });
	resetBrokerForTests();
	clearSuggestions();
});

interface HarnessOptions {
	script?: UiScript;
	models?: Array<{ id: string; provider: string }>;
	current?: { id: string; provider: string };
	/** `provider/id` -> family. Defaults to the provider. */
	families?: Record<string, string>;
	resolvedOverrides?: Partial<ResolvedConfig>;
	bypassActive?: boolean;
}

interface Harness {
	deps: CommandDeps;
	fake: FakeUi;
	writes: Array<Record<string, unknown>>;
	bypass: { active: boolean; reasons: string[]; disables: number };
	run(argv: string): Promise<string>;
}

function harness(options: HarnessOptions = {}): Harness {
	const fake = createFakeUi(options.script);
	const writes: Array<Record<string, unknown>> = [];
	const bypass = { active: options.bypassActive ?? false, reasons: [] as string[], disables: 0 };
	const models = options.models ?? [];
	let ids = 0;
	const effective: ResolvedConfig = { ...resolved, ...options.resolvedOverrides };

	const deps: CommandDeps = {
		resolved: effective,
		store,
		ui: fake.ui,
		now: () => clock,
		randomId: () => {
			ids += 1;
			return `id-${ids}`;
		},
		randomChallenge: () => CHALLENGE,
		recomputeHash: hashArguments,
		bypass: {
			active: () => bypass.active,
			enable: reason => {
				bypass.active = true;
				bypass.reasons.push(reason);
			},
			disable: () => {
				bypass.active = false;
				bypass.disables += 1;
			},
		},
		models: {
			list: () => models,
			current: () => options.current,
			family: model => options.families?.[`${model.provider}/${model.id}`] ?? model.provider,
		},
		writeConfig: async patch => {
			writes.push(patch);
			return path.join(root, "agent", "smart-approve.yml");
		},
	};

	const commands = createCommands(deps);
	return {
		deps,
		fake,
		writes,
		bypass,
		run: async argv => (await commands.run(argv)).lines.join("\n"),
	};
}

// ---------------------------------------------------------------------------
// Store seeding
// ---------------------------------------------------------------------------

function seedCall(
	auditId: string,
	overrides: Partial<PendingApproval> = {},
	/** The committed verdict, which `override` prefers over the pending record's copy. */
	committedOverrides: Partial<AuditRecord> = {},
): PendingApproval {
	store.beginAudit({
		auditId,
		toolCallId: `${auditId}-call`,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		sourceAgentId: "Researcher",
		sourceAgentKind: "sub",
		cwd: resolved.paths.cwd,
		retryFamilyKey: `family-${auditId}`,
		createdAt: NOW - 60_000,
	});
	store.commitAudit({
		auditId,
		toolCallId: `${auditId}-call`,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		sourceAgentId: "Researcher",
		sourceAgentKind: "sub",
		cwd: resolved.paths.cwd,
		decision: "escalate",
		stage: "escalation",
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		retryFamilyKey: `family-${auditId}`,
		retryCount: 0,
		createdAt: NOW - 60_000,
		...committedOverrides,
	});
	const record: PendingApproval = {
		auditId,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		nonce: `nonce-${auditId}`,
		sourceAgentId: "Researcher",
		cwd: resolved.paths.cwd,
		state: "awaiting-human",
		createdAt: NOW - 60_000,
		expiresAt: NOW + 3_600_000,
		exemptAttempts: 0,
		...overrides,
	};
	store.putPending(record);
	return record;
}

function frozen(args: Record<string, unknown> = ARGS): FrozenCall {
	return {
		toolName: "write",
		toolCallId: "call-1",
		rawArguments: Object.freeze({ ...args }),
		argumentsHash: hashArguments(args),
		frozenAt: NOW,
	};
}

function hold(auditId: string, args: Record<string, unknown> = ARGS): void {
	holdCall({ auditId, nonce: `nonce-${auditId}`, frozenCall: frozen(args), expiresAt: NOW + 600_000 });
}

function storedRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
	return {
		id: "rule-1",
		kind: "allow-exact",
		toolName: "write",
		target: "/srv/app/build.log",
		reason: "build log is disposable",
		createdBy: "human-override",
		specificity: 412,
		...overrides,
	};
}

/** A live allow grant for the seeded call, in `cwd`. */
function grantIn(id: string, cwd: string): Grant {
	return {
		id,
		auditId: "audit-a",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		cwd,
		scope: "persistent",
		expiresAt: NOW + 600_000,
		createdBy: "human",
		reason: "approved once",
	};
}

/** A committed verdict at an arbitrary instant, for window and aggregate claims. */
function commitDecision(auditId: string, createdAt: number): void {
	const begun = {
		auditId,
		toolCallId: `${auditId}-call`,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		argumentsHash: ARGS_HASH,
		canonicalHash: "canon-1",
		policyHash: resolved.policyHash,
		sourceAgentId: "Researcher",
		sourceAgentKind: "sub" as const,
		cwd: resolved.paths.cwd,
		retryFamilyKey: `family-${auditId}`,
		createdAt,
	};
	store.beginAudit(begun);
	store.commitAudit({
		...begun,
		decision: "block",
		stage: "judge",
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		retryCount: 0,
	});
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

describe("argument parsing", () => {
	test("no arguments prints usage covering every subcommand", async () => {
		const h = harness();
		const out = await h.run("");
		for (const name of ["setup", "status", "rules", "pending", "review", "override", "unguarded", "guarded"]) {
			expect(out).toContain(name);
		}
	});

	test("an unknown subcommand is named and does not silently no-op", async () => {
		const out = await harness().run("frobnicate");
		expect(out).toContain("Unknown subcommand `frobnicate`");
	});

	test("subcommands needing an audit ID say so instead of guessing", async () => {
		expect(await harness().run("review")).toContain("needs an audit ID");
		expect(await harness().run("override")).toContain("needs an audit ID");
		expect(await harness().run("apply-suggestion")).toContain("needs an audit ID");
	});
});

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

describe("setup", () => {
	const ANTHROPIC = { id: "claude-fast", provider: "anthropic" };
	const OPENAI = { id: "gpt-fast", provider: "openai" };

	test("with no authenticated model it writes nothing and never prompts", async () => {
		const h = harness({ models: [] });
		const out = await h.run("setup");
		expect(out).toContain("No model in this session has configured authentication");
		expect(out).toContain("Nothing was written");
		expect(h.writes).toHaveLength(0);
		expect(h.fake.confirms).toHaveLength(0);
	});

	test("recommends an authenticated model from a different family than the session model", async () => {
		const h = harness({
			models: [OPENAI, ANTHROPIC],
			current: OPENAI,
			families: { "openai/gpt-fast": "openai", "anthropic/claude-fast": "anthropic" },
		});
		const out = await h.run("setup");
		expect(out).toContain("Recommended judge: anthropic/claude-fast");
		expect(out).toContain("its family differs from the session model");
	});

	test("says so when only a same-family model is authenticated", async () => {
		const h = harness({ models: [OPENAI], current: OPENAI, families: { "openai/gpt-fast": "openai" } });
		const out = await h.run("setup");
		expect(out).toContain("Recommended judge: openai/gpt-fast");
		expect(out).toContain("No authorized model from a different family is available");
	});

	test("previews the config path and the timeout budget before asking", async () => {
		const h = harness({ models: [ANTHROPIC] });
		const out = await h.run("setup");
		expect(out).toContain("2 attempt(s) x 10000 ms + 1000 ms cleanup = 21000 ms worst case");
		expect(out).toContain("handler self-deadline 28000 ms");
		expect(out).toContain("smart-approve.yml");
	});

	test("cancelling writes nothing", async () => {
		const h = harness({ models: [ANTHROPIC], script: { confirms: [false] } });
		const out = await h.run("setup");
		expect(out).toContain("Cancelled. Nothing was written.");
		expect(h.writes).toHaveLength(0);
	});

	test("declining the write confirmation writes nothing, after a model was picked", async () => {
		const h = harness({ models: [ANTHROPIC], script: { selects: ["anthropic/claude-fast"], confirms: [false] } });
		const out = await h.run("setup");
		expect(h.fake.confirms).toHaveLength(1);
		expect(out).toContain("Selected judge: anthropic/claude-fast");
		expect(out).toContain("Cancelled. Nothing was written.");
		expect(h.writes).toHaveLength(0);
	});

	test("names the file it actually writes, even when a project layer is loaded", async () => {
		const userPath = path.join(root, "agent", "smart-approve.yml");
		const h = harness({
			models: [ANTHROPIC],
			script: { selects: ["anthropic/claude-fast"], confirms: [true] },
			resolvedOverrides: {
				layers: [
					{
						scope: "project",
						filePath: path.join(root, "project", ".omp", "smart-approve.yml"),
						contentHash: "c".repeat(64),
					},
				],
			},
		});
		const out = await h.run("setup");
		// The confirmed path is consent: naming a file other than the one the
		// writer touches would collect consent for a change that never happens.
		expect(h.fake.confirms[0]?.message).toContain(userPath);
		expect(out).toContain(`Config file: ${userPath}`);
		expect(out).toContain(`Wrote ${userPath}`);
	});

	test("confirming writes exactly the authorized-model patch, once", async () => {
		const h = harness({ models: [OPENAI, ANTHROPIC], script: { selects: ["openai/gpt-fast"], confirms: [true] } });
		const out = await h.run("setup");
		expect(h.writes).toEqual([{ judge: { authorizedModels: ["openai/gpt-fast"] } }]);
		expect(out).toContain(path.join(root, "agent", "smart-approve.yml"));
	});

	test("offers every authenticated model, recommended first and annotated", async () => {
		const h = harness({
			models: [OPENAI, ANTHROPIC],
			current: OPENAI,
			families: { "openai/gpt-fast": "openai", "anthropic/claude-fast": "anthropic" },
		});
		await h.run("setup");
		expect(h.fake.selects[0]?.title).toBe("Choose the judge model");
		expect(h.fake.selects[0]?.options.map(option => option.label)).toEqual([
			"anthropic/claude-fast",
			"openai/gpt-fast",
		]);
		expect(h.fake.selects[0]?.options[0]?.description).toContain(
			"recommended: differs from the session model's family",
		);
	});

	test("picking a model other than the recommendation authorizes the picked one", async () => {
		const h = harness({
			models: [OPENAI, ANTHROPIC],
			current: OPENAI,
			families: { "openai/gpt-fast": "openai", "anthropic/claude-fast": "anthropic" },
			script: { selects: ["openai/gpt-fast"], confirms: [true] },
		});
		const out = await h.run("setup");
		expect(h.writes).toEqual([{ judge: { authorizedModels: ["openai/gpt-fast"] } }]);
		expect(out).toContain("Selected judge: openai/gpt-fast");
		expect(h.fake.confirms[0]?.message).toContain('["openai/gpt-fast"]');
	});

	test("cancelling the picker writes nothing and never asks to confirm", async () => {
		const h = harness({ models: [ANTHROPIC] });
		const out = await h.run("setup");
		expect(out).toContain("Cancelled. Nothing was written.");
		expect(h.writes).toHaveLength(0);
		expect(h.fake.selects).toHaveLength(1);
		expect(h.fake.confirms).toHaveLength(0);
	});

	test("a label that was never offered is treated as cancel, not as consent", async () => {
		const h = harness({ models: [ANTHROPIC], script: { selects: ["openai/not-offered"], confirms: [true] } });
		const out = await h.run("setup");
		expect(out).toContain("Cancelled. Nothing was written.");
		expect(h.writes).toHaveLength(0);
		expect(h.fake.confirms).toHaveLength(0);
	});
});

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

describe("status", () => {
	test("reports the open-pending count together with the command that lists them", async () => {
		seedCall("audit-a");
		seedCall("audit-b");
		const out = await harness().run("status");
		expect(out).toContain("Open pending approvals: 2");
		expect(out).toContain("`/smart-approve pending`");
	});

	test("excludes records that already expired from the open count", async () => {
		seedCall("audit-a");
		seedCall("audit-old", { expiresAt: NOW - 1 });
		const out = await harness().run("status");
		expect(out).toContain("Open pending approvals: 1");
	});

	test("never leaks literal arguments even while the broker holds them", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness().run("status");
		expect(out).not.toContain(SECRET_CONTENT);
		expect(out).toContain("path:");
	});

	test("reports an unconfigured judge as not ready with the setup command", async () => {
		const out = await harness().run("status");
		expect(out).toContain("Gate: NOT READY");
		expect(out).toContain("no judge model authorized — run `/smart-approve setup`");
	});

	test("reports authorized models that this session cannot authenticate", async () => {
		const withModel: ResolvedConfig = {
			...resolved,
			config: {
				...resolved.config,
				judge: { ...resolved.config.judge, authorizedModels: ["anthropic/claude-fast"] },
			},
		};
		const out = await harness({ resolvedOverrides: withModel, models: [{ id: "gpt", provider: "openai" }] }).run(
			"status",
		);
		expect(out).toContain("authorized models are not available in this session: anthropic/claude-fast");
	});

	test("surfaces compatibility warnings rather than hiding them", async () => {
		const out = await harness({
			resolvedOverrides: { warnings: ["OMP 18 changed resolveApproval; host classification may drift"] },
		}).run("status");
		expect(out).toContain("Compatibility warnings:");
		expect(out).toContain("host classification may drift");
	});

	test("shows bypass state and broker health", async () => {
		const out = await harness({ bypassActive: true }).run("status");
		expect(out).toContain("UNGUARDED");
		expect(out).toContain("bypass:           ACTIVE (session only)");
		expect(out).toContain("main approval UI: ABSENT");
	});
});

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

describe("rules", () => {
	test("an allow-exact missing argumentsHash or cwd reads as advisory, not as a bypass", async () => {
		// The dangerous misreading: an operator sees "may skip the judge" on a rule
		// that is in fact still judged, and believes the gate is configured.
		store.putRule(storedRule());
		store.putRule(storedRule({ id: "rule-2", kind: "allow-pattern", target: "/srv/app/**", specificity: 210 }));
		const out = await harness().run("rules");
		expect(out).toContain("advisory posture — still judged (no argumentsHash, no cwd)");
		expect(out).toContain("posture hint only — never skips the judge");
		expect(out).not.toContain("skips the judge for this precise call");
	});

	test("a fully qualified allow-exact reads as a real bypass", async () => {
		store.putRule(
			storedRule({
				id: "rule-pinned",
				argumentsHash: "a".repeat(64),
				cwd: resolved.paths.cwd,
			}),
		);
		const out = await harness().run("rules");
		expect(out).toContain("skips the judge for this precise call in this directory");
	});

	test("posture degrades the moment any one condition is missing", async () => {
		store.putRule(storedRule({ id: "no-hash", cwd: resolved.paths.cwd }));
		store.putRule(storedRule({ id: "no-cwd", argumentsHash: "a".repeat(64) }));
		store.putRule(
			storedRule({ id: "patterned", target: "/srv/**", argumentsHash: "a".repeat(64), cwd: resolved.paths.cwd }),
		);
		const out = await harness().run("rules");
		expect(out).toContain("advisory posture — still judged (no argumentsHash)");
		expect(out).toContain("advisory posture — still judged (no cwd)");
		expect(out).toContain("advisory posture — still judged (target is a pattern)");
	});

	test("a pinned rule from a project file reads as advisory, not as a bypass", async () => {
		// A `smart-approve.yml` arriving with `git clone` is not an operator
		// decision, so `matchExactAllow` refuses it — this label has to agree.
		const configured = storedRule({
			id: "cfg-pin",
			createdBy: "project",
			source: "/repo/.omp/smart-approve.yml",
			argumentsHash: "a".repeat(64),
			cwd: resolved.paths.cwd,
		});
		const out = await harness({ resolvedOverrides: { rules: [configured] } }).run("rules");
		expect(out).toContain("advisory posture — still judged (project-scope file)");
		expect(out).not.toContain("skips the judge for this precise call");
	});

	test("a pinned rule with a relative cwd reads as advisory, not as a bypass", async () => {
		store.putRule(storedRule({ id: "rel-cwd", argumentsHash: "a".repeat(64), cwd: "." }));
		const out = await harness().run("rules");
		expect(out).toContain("advisory posture — still judged (cwd is not absolute)");
		expect(out).not.toContain("skips the judge for this precise call");
	});

	test("show explains a relative cwd and a project scope rather than printing them bare", async () => {
		store.putRule(storedRule({ id: "rel-cwd", argumentsHash: "a".repeat(64), cwd: "./sub" }));
		expect(await harness().run("rules show rel-cwd")).toContain(
			"cwd:         ./sub (relative — cannot skip the judge)",
		);

		const configured = storedRule({ id: "cfg-pin", createdBy: "project", source: "/repo/smart-approve.yml" });
		const out = await harness({ resolvedOverrides: { rules: [configured] } }).run("rules show cfg-pin");
		expect(out).toContain("created by:  project (project scope never skips the judge)");
	});

	test("show names the missing field so the operator can fix it", async () => {
		store.putRule(storedRule());
		const out = await harness().run("rules show rule-1");
		expect(out).toContain("argsHash:    (absent — cannot skip the judge)");
		expect(out).toContain("cwd:         (absent — cannot skip the judge)");
	});

	test("show renders one rule with its posture and specificity", async () => {
		store.putRule(storedRule());
		const out = await harness().run("rules show rule-1");
		expect(out).toContain("Rule rule-1");
		expect(out).toContain("target:      /srv/app/build.log (exact)");
		expect(out).toContain("specificity: 412");
	});

	test("revoke without confirmation changes nothing", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant({
			id: "grant-1",
			auditId: "audit-a",
			argumentsHash: ARGS_HASH,
			canonicalHash: "canon-1",
			policyHash: resolved.policyHash,
			cwd: resolved.paths.cwd,
			scope: "session",
			expiresAt: NOW + 600_000,
			createdBy: "human",
			reason: "approved once",
		});

		const out = await harness({ script: { confirms: [false] } }).run("rules revoke rule-1");
		expect(out).toContain("Cancelled");
		expect(store.listRules()).toHaveLength(1);
		expect(store.listGrants()).toHaveLength(1);
	});

	test("confirmed revoke removes the rule and invalidates outstanding grants", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant({
			id: "grant-1",
			auditId: "audit-a",
			argumentsHash: ARGS_HASH,
			canonicalHash: "canon-1",
			policyHash: resolved.policyHash,
			cwd: resolved.paths.cwd,
			scope: "persistent",
			expiresAt: NOW + 600_000,
			createdBy: "human",
			reason: "approved once",
		});

		const out = await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		expect(out).toContain("Revoked rule rule-1");
		expect(out).toContain("Invalidated 1 outstanding allow grant(s)");
		expect(store.listRules()).toHaveLength(0);
		expect(store.findGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeUndefined();
	});

	test("a configuration rule cannot be revoked from the command", async () => {
		const configured: PolicyRule = storedRule({ id: "cfg-1", createdBy: "project", source: "smart-approve.yml" });
		const out = await harness({ resolvedOverrides: { rules: [configured] } }).run("rules revoke cfg-1");
		expect(out).toContain("cannot be revoked here");
		expect(out).toContain("Edit the configuration file");
	});
});

// ---------------------------------------------------------------------------
// pending
// ---------------------------------------------------------------------------

describe("pending", () => {
	test("works with no arguments and lists the open record", async () => {
		seedCall("audit-a");
		const out = await harness().run("pending");
		expect(out).toContain("1 open Smart Approve escalation:");
		expect(out).toContain("audit-a");
		expect(out).toContain("path:/etc/shadow");
		expect(out).toContain("destructive-action");
		expect(out).toContain("Researcher");
	});

	test("reports mintability from the live broker", async () => {
		seedCall("audit-a");
		hold("audit-a");
		expect(await harness().run("pending")).toContain("can mint an exact grant");
	});

	test("after a restart with an empty broker every record is intent-only", async () => {
		seedCall("audit-a");
		hold("audit-a");
		// Simulate the process dying: durable records survive, in-memory ones do not.
		resetBrokerForTests();
		const out = await harness().run("pending");
		expect(out).toContain("audit-a");
		expect(out).toContain("intent-only. The literal arguments are gone");
		expect(out).not.toContain("can mint an exact grant");
	});

	test("excludes resolved and expired records", async () => {
		seedCall("audit-open");
		seedCall("audit-denied");
		seedCall("audit-stale", { expiresAt: NOW - 1 });
		store.updatePendingState("audit-denied", "denied", NOW);

		const out = await harness().run("pending");
		expect(out).toContain("1 open Smart Approve escalation:");
		expect(out).toContain("audit-open");
		expect(out).not.toContain("audit-denied");
		expect(out).not.toContain("audit-stale");
	});

	test("sweeps timed-out waits into expired while listing", async () => {
		seedCall("audit-stale", { expiresAt: NOW - 1 });
		await harness().run("pending");
		expect(store.getPending("audit-stale")?.state).toBe("expired");
	});

	test("says plainly when nothing is open", async () => {
		expect(await harness().run("pending")).toContain("No Smart Approve escalations are open");
	});
});

// ---------------------------------------------------------------------------
// review
// ---------------------------------------------------------------------------

describe("review", () => {
	test("renders the immutable verdict, event history, and retry family", async () => {
		seedCall("audit-a");
		store.appendEvent({ auditId: "audit-a", type: "judged", detail: "escalate", actor: "judge", at: NOW - 59_000 });
		store.appendEvent({
			auditId: "audit-a",
			type: "escalated",
			detail: "pending approval opened",
			actor: "gate",
			at: NOW - 58_000,
		});
		store.recordStrike("family-audit-a", "audit-a", NOW - 58_000);

		const out = await harness().run("review audit-a");
		expect(out).toContain("Original verdict (immutable)");
		expect(out).toContain("decision: escalate at stage escalation");
		expect(out).toContain("judged");
		expect(out).toContain("pending approval opened");
		expect(out).toContain("Retry family: family-audit-a. Strikes: 1.");
	});

	test("renders literal arguments only while the broker holds them", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness().run("review audit-a");
		expect(out).toContain("(from the live in-memory broker)");
		expect(out).toContain(SECRET_CONTENT);
		expect(out).toContain("It can mint an exact grant");
	});

	test("never reconstructs arguments from persistence once the broker is empty", async () => {
		seedCall("audit-a");
		const out = await harness().run("review audit-a");
		expect(out).not.toContain(SECRET_CONTENT);
		expect(out).toContain("never");
		expect(out).toContain("nothing here is reconstructed from the audit database");
		expect(out).toContain("Intent-only. The literal arguments are gone");
	});

	test("leads with the SBAR when the record carries decision support", async () => {
		seedCall("audit-a", {
			context: {
				userIntent: "rotate the service account password",
				agentRationale: "writing the new password file",
				rationaleFreshness: "current-turn",
				rationaleFromReasoning: false,
				flaggedBy: "judge",
			},
		});

		const out = await harness().run("review audit-a");
		expect(out).toContain(
			"S  Held for your decision: write write targeting path:/etc/shadow. Risk: destructive-action.",
		);
		expect(out).toContain(`B  You asked: "rotate the service account password".`);
		expect(out).toContain(`   Agent's reason: "writing the new password file" (stated this turn).`);
		expect(out).toContain("A  Flagged by the judge: overwrites the system password database.");
		expect(out).toContain("R  Deny unless this matches what you asked for.");
	});

	test("says a record predates context capture rather than showing an empty block", async () => {
		seedCall("audit-a");

		const out = await harness().run("review audit-a");
		expect(out).toContain("(recorded before context capture)");
		expect(out).not.toContain("Held for your decision");
	});

	test("shows a live judge suggestion", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files are never an agent target",
		});
		const out = await harness().run("review audit-a");
		expect(out).toContain("deny-pattern write -> /etc/**");
		expect(out).toContain("Non-binding");
	});

	test("an unknown audit ID is reported, not invented", async () => {
		expect(await harness().run("review audit-missing")).toContain(
			"No Smart Approve record for audit ID audit-missing",
		);
	});
});

// ---------------------------------------------------------------------------
// apply-suggestion
// ---------------------------------------------------------------------------

describe("apply-suggestion", () => {
	test("refuses when no suggestion is held in memory", async () => {
		seedCall("audit-a");
		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(out).toContain("No live judge suggestion");
		expect(store.listRules()).toHaveLength(0);
	});

	test("a model-suggested wildcard allow stays non-bypass posture even after confirmation", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "allow-exact",
			toolName: "write",
			target: "/srv/app/**",
			rationale: "the build directory is disposable",
		});

		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(out).toContain("normalized:  allow-pattern");
		expect(out).toContain("downgraded to a posture hint and still cannot skip the judge");

		const rules = store.listRules();
		expect(rules).toHaveLength(1);
		expect(rules[0]?.kind).toBe("allow-pattern");
	});

	test("an exact allow with no pattern operator is kept exact", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "allow-exact",
			toolName: "write",
			target: "/srv/app/build.log",
			rationale: "one disposable file",
		});
		await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(store.listRules()[0]?.kind).toBe("allow-exact");
	});

	test("declining the confirmation inserts nothing", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files",
		});
		const out = await harness({ script: { confirms: [false] } }).run("apply-suggestion audit-a");
		expect(out).toContain("Cancelled. No rule was inserted.");
		expect(store.listRules()).toHaveLength(0);
	});

	test("the confirmation the operator answers cannot be forged by the suggestion", async () => {
		// This confirm authorizes a policy-rule insert, so the model-authored target
		// and rationale reach an authorization surface. The rule that gets inserted
		// must still carry the raw target: escaping it would change what it matches.
		const hostileTarget = "/etc/**\u001b[2K\u001b[1A\n  posture:     exact allow";
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: hostileTarget,
			rationale: "system files\u0085  specificity: 9999",
		});
		const h = harness({ script: { confirms: [true] } });

		await h.run("apply-suggestion audit-a");

		// The message is rows joined by real newlines, so check each row rather than
		// the joined string: only the rows themselves must be control-free.
		const rows = (h.fake.confirms[0]?.message ?? "").split("\n");
		for (const row of rows) expect(row).not.toMatch(/[\p{Cc}\p{Zl}\p{Zp}]/u);
		expect(rows.filter(row => row.trimStart().startsWith("posture:"))).toHaveLength(1);
		expect(rows.filter(row => row.trimStart().startsWith("specificity:"))).toHaveLength(1);
		const asked = rows.join("\n");
		// Defanged for display only; the stored rule keeps the target it will match on.
		expect(asked).toContain("\\u001b");
		expect(store.listRules()[0]?.target).toBe(hostileTarget);
	});

	test("a suggestion that fails the rule schema is rejected before insertion", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", { kind: "deny-exact", toolName: "write", target: "", rationale: "empty target" });
		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(out).toContain("does not validate and was not inserted");
		expect(store.listRules()).toHaveLength(0);
	});

	test("an applied suggestion is linked to the originating audit", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files",
		});
		await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		const events = store.listEvents("audit-a");
		expect(events.some(e => e.type === "overridden" && e.detail.includes("deny-pattern"))).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// override
// ---------------------------------------------------------------------------

const SCOPE_ONE_TIME = GRANT_SCOPE_OPTIONS[0]?.label ?? "";
const SCOPE_SESSION = GRANT_SCOPE_OPTIONS[1]?.label ?? "";
const SCOPE_PERSISTENT = GRANT_SCOPE_OPTIONS[2]?.label ?? "";

describe("override", () => {
	test("the verdict is on screen before the chooser opens, not only in the transcript", async () => {
		// The returned lines are printed after the command finishes. If that were the
		// only place the context appeared, the operator would be picking between
		// deny, expire, and approve with nothing but an audit ID in front of them.
		seedCall("audit-a");
		const h = harness();

		const out = await h.run("override audit-a");

		const shown = h.fake.selects[0]?.onScreen[WIDGET_OVERRIDE]?.join("\n") ?? "";
		expect(shown).toContain("Original verdict (append-only; nothing below rewrites it)");
		expect(shown).toContain("escalate at stage escalation");
		expect(shown).toContain("overwrites the system password database");
		expect(shown).toContain("target: path:/etc/shadow");
		// And it is torn down again rather than left on screen afterwards.
		expect(h.fake.widgets.at(-1)).toEqual({ key: WIDGET_OVERRIDE, lines: undefined });
		expect(out).toContain("Original verdict (append-only; nothing below rewrites it)");
	});

	test("the context is cleared even when the chooser throws", async () => {
		seedCall("audit-a");
		const h = harness({
			script: {
				onSelect: () => {
					throw new Error("the TUI went away");
				},
			},
		});

		await expect(h.run("override audit-a")).rejects.toThrow("the TUI went away");
		expect(h.fake.widgets.at(-1)).toEqual({ key: WIDGET_OVERRIDE, lines: undefined });
	});

	test("a legacy row's stored newline cannot forge a row in the decision context", async () => {
		// Written before `escapeSummary` existed and still live under
		// `pendingApprovalTtl`. This block is what the operator reads while the
		// deny / expire / approve chooser is open, so a forged row here is the most
		// consequential of all.
		seedCall("audit-a", {
			targetSummary: "path:/repo/notes.md\n  target: path:/repo/safe.md\n  verified: yes",
		});
		const h = harness();

		await h.run("override audit-a");

		const shown = h.fake.selects[0]?.onScreen[WIDGET_OVERRIDE] ?? [];
		expect(shown.length).toBeGreaterThan(0);
		// Neither forged row becomes a row of its own; both stay inside the real one.
		const rows = shown.map(line => line.trimStart());
		expect(rows.filter(line => line.startsWith("target:"))).toHaveLength(1);
		expect(rows.filter(line => line.startsWith("verified:"))).toHaveLength(0);
		// Defanged, not hidden: the operator still sees what the agent actually asked for.
		expect(shown.join("\n")).toContain("\\n");
		expect(shown.join("\n")).toContain("path:/repo/notes.md");
	});

	test("an injected judge rationale cannot forge a row in the decision context either", async () => {
		// The rationale is model output, so a prompt-injected judge is a live writer
		// into this block. Before the widget existed this text only reached the
		// post-decision transcript; now it is read while the chooser is open.
		// `override` prefers the committed verdict, so that is what must be seeded.
		seedCall("audit-a", {}, { rationale: "looks routine\n  risk:   uncertain\n  verified: approved by policy" });
		const h = harness();

		await h.run("override audit-a");

		const shown = h.fake.selects[0]?.onScreen[WIDGET_OVERRIDE] ?? [];
		const rows = shown.map(line => line.trimStart());
		expect(rows.filter(line => line.startsWith("risk:"))).toHaveLength(1);
		expect(rows.filter(line => line.startsWith("verified:"))).toHaveLength(0);
		expect(rows.filter(line => line.startsWith("risk:"))[0]).toBe("risk:   destructive-action");
		// Defanged in place, not dropped: the operator still reads what the judge said.
		expect(shown.join("\n")).toContain("looks routine\\n  risk:   uncertain\\n  verified: approved by policy");
	});

	test("a 2000-character rationale cannot swamp the decision context", async () => {
		seedCall("audit-a", {}, { rationale: "r".repeat(2_000) });
		const h = harness();

		await h.run("override audit-a");

		const shown = h.fake.selects[0]?.onScreen[WIDGET_OVERRIDE] ?? [];
		expect(shown.every(line => line.length < 300)).toBe(true);
		expect(shown.join("\n")).toContain("chars total");
	});

	test("a mismatched challenge changes nothing and is recorded", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE], inputs: ["not-the-challenge"] },
		}).run("override audit-a");

		expect(out).toContain("Challenge did not match");
		expect(store.getPending("audit-a")?.state).toBe("awaiting-human");
		expect(store.listGrants()).toHaveLength(0);
		expect(store.listEvents("audit-a").some(e => e.detail.includes("override challenge failed"))).toBe(true);
	});

	test("cancelling the action prompt changes nothing", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness().run("override audit-a");
		expect(out).toContain("Cancelled. Nothing changed.");
		expect(store.getPending("audit-a")?.state).toBe("awaiting-human");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("a one-time grant is minted from the live literal arguments", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "verified by hand"] },
		}).run("override audit-a");

		expect(out).toContain(`Granted a one-time allow bound to call hash ${ARGS_HASH}`);
		const grants = store.listGrants();
		expect(grants).toHaveLength(1);
		expect(grants[0]?.scope).toBe("one-time");
		expect(grants[0]?.argumentsHash).toBe(ARGS_HASH);
		expect(grants[0]?.reason).toBe("verified by hand");
		expect(store.getPending("audit-a")?.state).toBe("approved-granted");

		const types = store.listEvents("audit-a").map(e => e.type);
		expect(types).toContain("overridden");
		expect(types).toContain("granted");
	});

	test("a one-time grant is consumed exactly once", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeDefined();
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeUndefined();
	});

	test("a session grant outlives the in-memory arguments", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_SESSION], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		const grant = store.listGrants()[0];
		expect(grant?.scope).toBe("session");
		expect(grant?.expiresAt).toBe(NOW + resolved.config.timeouts.pendingApprovalTtlMs);
	});

	test("a persistent grant needs a second explicit confirmation", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const declined = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_PERSISTENT], inputs: [CHALLENGE, "ok"], confirms: [false] },
		}).run("override audit-a");

		expect(declined).toContain("needs a second explicit confirmation. Nothing was granted.");
		expect(store.listGrants()).toHaveLength(0);
		expect(store.getPending("audit-a")?.state).toBe("awaiting-human");
	});

	test("a persistent grant is minted once the second confirmation arrives", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const h = harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_PERSISTENT], inputs: [CHALLENGE, "ok"], confirms: [true] },
		});
		await h.run("override audit-a");

		expect(store.listGrants()[0]?.scope).toBe("persistent");
		expect(h.fake.confirms).toHaveLength(1);
		expect(h.fake.confirms[0]?.title).toBe("Persistent allow");
	});

	test("evicted arguments refuse a grant and record intent to approve instead", async () => {
		seedCall("audit-a");
		// No hold(): a restart, subagent teardown, or broker TTL expiry got here first.
		const out = await harness({
			script: {
				selects: [OVERRIDE_APPROVE, SCOPE_PERSISTENT],
				inputs: [CHALLENGE, "still want it"],
				confirms: [true],
			},
		}).run("override audit-a");

		expect(out).toContain("No grant was minted");
		expect(out).toContain("Recorded intent to approve only");
		expect(out).toContain("re-opens a live approval dialog");
		expect(store.listGrants()).toHaveLength(0);
		expect(store.getPending("audit-a")?.state).toBe("approved-intent");
		expect(store.listEvents("audit-a").some(e => e.type === "intent-recorded")).toBe(true);
	});

	test("held arguments whose hash no longer matches refuse a grant", async () => {
		seedCall("audit-a");
		hold("audit-a", { path: "/etc/shadow", content: "different bytes" });
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		expect(out).toContain("No grant was minted");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("a policy change since the block refuses a grant", async () => {
		seedCall("audit-a", { policyHash: "policy-from-yesterday" });
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		expect(out).toContain("Configuration or policy changed since this call was blocked");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("deny works without the literal arguments", async () => {
		seedCall("audit-a");
		const out = await harness({ script: { selects: [OVERRIDE_DENY], inputs: [CHALLENGE] } }).run(
			"override audit-a",
		);
		expect(out).toContain("Denied. The block stands");
		expect(store.getPending("audit-a")?.state).toBe("denied");
		expect(store.listEvents("audit-a").some(e => e.type === "denied")).toBe(true);
	});

	test("expire works without the literal arguments", async () => {
		seedCall("audit-a");
		const out = await harness({ script: { selects: [OVERRIDE_EXPIRE], inputs: [CHALLENGE] } }).run(
			"override audit-a",
		);
		expect(out).toContain("Expired");
		expect(store.getPending("audit-a")?.state).toBe("expired");
	});

	test("a resolved record cannot be reopened", async () => {
		seedCall("audit-a");
		store.updatePendingState("audit-a", "denied", NOW);
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");
		expect(out).toContain("already resolved (denied)");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("a record past its pending TTL is swept to expired and cannot be actioned", async () => {
		seedCall("audit-a", { expiresAt: NOW - 1 });
		const out = await harness({ script: { selects: [OVERRIDE_DENY], inputs: [CHALLENGE] } }).run(
			"override audit-a",
		);
		expect(out).toContain("already resolved (expired)");
		expect(store.getPending("audit-a")?.state).toBe("expired");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("an approved-intent record past its TTL is refused rather than granted", async () => {
		seedCall("audit-a", { expiresAt: NOW - 1 });
		store.updatePendingState("audit-a", "approved-intent", NOW - 2);
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "too late"] },
		}).run("override audit-a");

		expect(out).toContain("no longer be actioned");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("an unknown audit ID points at the pending list", async () => {
		const out = await harness().run("override audit-missing");
		expect(out).toContain("No Smart Approve escalation with audit ID audit-missing");
		expect(out).toContain("/smart-approve pending");
	});

	test("an approved-intent record can still be approved once its arguments return", async () => {
		seedCall("audit-a");
		await harness({ script: { selects: [OVERRIDE_APPROVE], inputs: [CHALLENGE, "later"] } }).run(
			"override audit-a",
		);
		expect(store.getPending("audit-a")?.state).toBe("approved-intent");

		// The agent retries; the gate freezes the identical call again.
		hold("audit-a");
		await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "now verified"] },
		}).run("override audit-a");

		expect(store.listGrants()).toHaveLength(1);
		expect(store.getPending("audit-a")?.state).toBe("approved-granted");
	});
});

// ---------------------------------------------------------------------------
// bypass
// ---------------------------------------------------------------------------

describe("unguarded and guarded", () => {
	test("a mismatched challenge leaves the gate on", async () => {
		const h = harness({ script: { inputs: ["nope"] } });
		const out = await h.run("unguarded");
		expect(out).toContain("Smart Approve stays on");
		expect(h.bypass.active).toBe(false);
		expect(h.bypass.reasons).toHaveLength(0);
	});

	test("cancelling the challenge prompt leaves the gate on", async () => {
		const h = harness({ script: { inputs: [undefined] } });
		await h.run("unguarded");
		expect(h.bypass.active).toBe(false);
	});

	test("a typed challenge enables a session-scoped bypass with a persistent warning", async () => {
		const h = harness({ script: { inputs: [CHALLENGE, "debugging a broken sandbox"] } });
		const out = await h.run("unguarded");

		expect(h.bypass.active).toBe(true);
		expect(h.bypass.reasons).toEqual(["debugging a broken sandbox"]);
		expect(out).toContain("Smart Approve is UNGUARDED for this session");
		expect(out).toContain("bypass ends when this session ends");

		const widget = h.fake.widgets.find(w => w.key === WIDGET_BYPASS);
		expect(widget?.lines?.join("\n")).toContain("SMART APPROVE IS UNGUARDED");
		expect(h.fake.statuses).toContainEqual({
			key: STATUS_KEY,
			text: "UNGUARDED — calls OMP would run unattended are not judged",
		});
		expect(h.fake.notices.some(n => n.type === "error")).toBe(true);
	});

	test("enabling a bypass appends an immutable audit event and persists no bypass state", async () => {
		const h = harness({ script: { inputs: [CHALLENGE, "reason"] } });
		const out = await h.run("unguarded");

		const auditId = /Audit ID: (\S+)/.exec(out)?.[1];
		expect(auditId).toBeDefined();
		const events = store.listEvents(auditId ?? "");
		expect(events.map(e => e.type)).toEqual(["bypass-enabled"]);
		expect(events[0]?.actor).toBe("human");

		// The bypass lives in session memory only: nothing durable can revive it.
		expect(store.listRules()).toHaveLength(0);
		expect(store.listGrants()).toHaveLength(0);
		expect(h.writes).toHaveLength(0);
	});

	test("guarded re-enables immediately, clears the warning, and audits it", async () => {
		const h = harness({ script: { inputs: [CHALLENGE, "reason"] } });
		await h.run("unguarded");
		const out = await h.run("guarded");

		expect(h.bypass.active).toBe(false);
		expect(h.bypass.disables).toBe(1);
		expect(out).toContain("Smart Approve is guarded again");
		expect(h.fake.widgets.at(-1)).toEqual({ key: WIDGET_BYPASS, lines: undefined });
		expect(h.fake.statuses.at(-1)).toEqual({ key: STATUS_KEY, text: undefined });

		const auditId = /Audit ID: (\S+)/.exec(out)?.[1];
		expect(store.listEvents(auditId ?? "").map(e => e.type)).toEqual(["bypass-disabled"]);
	});

	test("guarded is idempotent and does not fabricate an audit event", async () => {
		const h = harness();
		const out = await h.run("guarded");
		expect(out).toContain("already guarded");
		expect(out).not.toContain("Audit ID");
	});

	test("no configuration key can silently disable the gate", () => {
		const defaults = smartApproveConfigSchema.parse({});
		const keys: string[] = [];
		const walk = (value: unknown, prefix: string): void => {
			if (value === null || typeof value !== "object" || Array.isArray(value)) return;
			for (const [key, child] of Object.entries(value)) {
				const full = prefix === "" ? key : `${prefix}.${key}`;
				keys.push(full);
				walk(child, full);
			}
		};
		walk(defaults, "");

		expect(keys.length).toBeGreaterThan(20);
		for (const key of keys) {
			expect(key).not.toMatch(/bypass|unguarded|disabl|yolo|skip/i);
		}

		// The schema is strict, so a future "off switch" cannot be smuggled in either.
		expect(smartApproveConfigSchema.safeParse({ ...defaults, disabled: true }).success).toBe(false);
		expect(
			smartApproveConfigSchema.safeParse({ ...defaults, judge: { ...defaults.judge, bypass: true } }).success,
		).toBe(false);
	});
});

describe("rule revocation is global, exactly as its confirm dialog promises", () => {
	// The dialog is a safety lever a human reads before pulling it. If it says
	// "every outstanding allow grant" it must mean every one, not this directory's.
	const OTHER_REPO = "/srv/other-checkout";

	test("the confirm dialog states the scope it actually has", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		const h = harness({ script: { confirms: [false] } });
		await h.run("rules revoke rule-1");
		const asked = h.fake.confirms.at(-1)?.message ?? "";
		expect(asked).toContain("every");
		expect(asked).toContain("other working directory");
	});

	test("revoking clears a grant held in a different checkout", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("here", resolved.paths.cwd));
		store.putGrant(grantIn("elsewhere", OTHER_REPO));

		const out = await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		expect(out).toContain("Invalidated 2 outstanding allow grant(s), across every working directory");
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, OTHER_REPO, NOW)).toBeUndefined();
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeUndefined();
	});

	test("the count means grants that could still admit a call, not every row", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("live", resolved.paths.cwd));
		store.putGrant({ ...grantIn("spent", resolved.paths.cwd), consumedAt: NOW - 1_000 });
		store.putGrant({ ...grantIn("lapsed", resolved.paths.cwd), expiresAt: NOW - 1 });

		const out = await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		// Only the live one could have admitted anything; calling three "outstanding"
		// would overstate what the operator just prevented.
		expect(out).toContain("Invalidated 1 outstanding allow grant(s)");
	});

	test("spent and lapsed grants survive revocation as audit history", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("live", resolved.paths.cwd));
		store.putGrant({ ...grantIn("spent", resolved.paths.cwd), consumedAt: NOW - 1_000 });
		store.putGrant({ ...grantIn("lapsed", resolved.paths.cwd), expiresAt: NOW - 1 });

		await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		// A consumed grant records what actually ran. Erasing it would destroy
		// evidence, and it can authorize nothing, so revocation leaves it alone.
		const remaining = store
			.listGrants()
			.map(g => g.id)
			.sort();
		expect(remaining).toEqual(["lapsed", "spent"]);
	});

	test("cancelling revokes nothing anywhere", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putGrant(grantIn("elsewhere", OTHER_REPO));
		await harness({ script: { confirms: [false] } }).run("rules revoke rule-1");
		expect(store.listGrants()).toHaveLength(1);
	});
});

// ---------------------------------------------------------------------------
// Operator-facing text
//
// Every test below takes one sentence the software shows a human, builds the
// case that sentence rules out, and fails if the sentence is not true of it.
// Asserting a string is present is not asserting it is true.
// ---------------------------------------------------------------------------

describe("setup states what it will not do, and does not do it", () => {
	test("never falls back to the session model, even when one is answering prompts", async () => {
		// The dangerous reading: "no authenticated model" means "none at all", so an
		// operator assumes setup would have used the model they are chatting with.
		const h = harness({ models: [], current: { id: "gpt-fast", provider: "openai" } });
		const out = await h.run("setup");

		expect(out).toContain("never falls back to the primary session model");
		expect(out).toContain("Nothing was written");
		expect(out).not.toContain("gpt-fast");
		expect(h.writes).toHaveLength(0);
		expect(h.fake.confirms).toHaveLength(0);
	});
});

describe("status reports what it read, not what it assumed", () => {
	test("the selected judge can authenticate here; it is not just the first authorized", async () => {
		const twoAuthorized: ResolvedConfig = {
			...resolved,
			config: {
				...resolved.config,
				judge: {
					...resolved.config.judge,
					authorizedModels: ["anthropic/claude-fast", "openai/gpt-fast"],
				},
			},
		};
		const out = await harness({
			resolvedOverrides: twoAuthorized,
			models: [{ id: "gpt-fast", provider: "openai" }],
		}).run("status");

		expect(out).toContain("1 of 2 authorized model(s) available with auth");
		expect(out).toContain("selected:   openai/gpt-fast");
		expect(out).toContain("auth:       healthy");
	});

	test("an unreadable database reads as unknown, never as an all-clear", async () => {
		seedCall("audit-a");
		commitDecision("audit-decided", NOW - 60_000);
		// One escalation is open and one decision is committed, so zeroes below would
		// be fabrications rather than an empty database.
		store.close();

		const out = await harness().run("status");
		expect(out).toContain("health: FAILING");
		expect(out).toContain("Open pending approvals: unknown — the audit database could not be read");
		expect(out).not.toContain("Open pending approvals: 0");
		expect(out).not.toContain("total 0");
	});

	test("the 24h heading means 24h: an older decision is not counted", async () => {
		commitDecision("audit-inside", NOW - 60_000);
		commitDecision("audit-outside", NOW - 25 * 60 * 60_000);

		const out = await harness().run("status");
		expect(out).toContain("Recent decisions (last 24h 00m):");
		expect(out).toContain("total 1  allow 0  escalate 0  block 1");
	});

	test("the approval channel reads live only when a main interactive endpoint exists", async () => {
		expect(await harness().run("status")).toContain(
			"main approval UI: ABSENT — escalations block instead of prompting",
		);

		registerEndpoint({
			agentId: "Main",
			agentKind: "main",
			capability: "interactive",
			present: async () => undefined,
		});
		expect(await harness().run("status")).toContain("main approval UI: live");
	});

	test("a headless session is called headless", async () => {
		expect(await harness({ script: { hasUI: false } }).run("status")).toContain("this session UI:  headless");
	});
});

describe("rules text is derived from the matching predicate, not from kind", () => {
	const TARGETS: readonly CallTarget[] = [
		{ kind: "path", requested: "/srv/app/build.log", resolved: "/srv/app/build.log", dynamic: false },
	];

	test("the footer sentence is true: only the fully pinned allow skips the judge", async () => {
		const complete = storedRule({ id: "pinned", argumentsHash: ARGS_HASH, cwd: resolved.paths.cwd });
		const noHash = storedRule({ id: "no-hash", cwd: resolved.paths.cwd });
		const noCwd = storedRule({ id: "no-cwd", argumentsHash: ARGS_HASH });
		const patterned = storedRule({
			id: "patterned",
			target: "/srv/app/**",
			argumentsHash: ARGS_HASH,
			cwd: resolved.paths.cwd,
		});
		for (const rule of [complete, noHash, noCwd, patterned]) store.putRule(rule);

		// The sentence's claim, asked of the predicate the gate actually applies.
		expect(matchExactAllow([complete], "write", ARGS_HASH, TARGETS, resolved.paths.cwd)?.id).toBe("pinned");
		for (const rule of [noHash, noCwd, patterned]) {
			expect(matchExactAllow([rule], "write", ARGS_HASH, TARGETS, resolved.paths.cwd)).toBeUndefined();
		}

		const out = await harness().run("rules");
		expect(out).toContain("An allow skips the judge only when it is exact AND pins the call with an");
		// Four rules listed, one bypass label: the labels track the predicate.
		expect(out.match(/skips the judge for this precise call/g)).toHaveLength(1);
	});

	test("the origin column distinguishes a config rule from a stored one", async () => {
		store.putRule(storedRule({ id: "stored-1" }));
		const configured = storedRule({ id: "cfg-1", createdBy: "project", source: "smart-approve.yml" });
		const out = await harness({ resolvedOverrides: { rules: [configured] } }).run("rules");

		expect(out).toContain("From configuration (1):");
		expect(out).toContain("Stored in the audit database (1):");
		expect(out).toContain("cfg-1  [allow-exact]  config");
		expect(out).toContain("stored-1  [allow-exact]  store");
	});

	test("show names each missing field on its own, as the footer promises", async () => {
		store.putRule(storedRule({ id: "no-hash", cwd: resolved.paths.cwd }));
		store.putRule(storedRule({ id: "no-cwd", argumentsHash: "a".repeat(64) }));

		const noHash = await harness().run("rules show no-hash");
		expect(noHash).toContain("argsHash:    (absent — cannot skip the judge)");
		expect(noHash).toContain(`cwd:         ${resolved.paths.cwd}`);

		const noCwd = await harness().run("rules show no-cwd");
		expect(noCwd).toContain("cwd:         (absent — cannot skip the judge)");
		expect(noCwd).toContain(`argsHash:    ${"a".repeat(64)}`);
	});

	test("show labels a pattern target as a pattern", async () => {
		store.putRule(storedRule({ id: "rule-p", target: "/srv/app/**" }));
		expect(await harness().run("rules show rule-p")).toContain("target:      /srv/app/** (pattern)");
	});

	test("every action the error message names actually works", async () => {
		store.putRule(storedRule());
		expect(await harness().run("rules frobnicate")).toContain("Use list, show, or revoke.");
		expect(await harness().run("rules list")).toContain("SMART APPROVE RULES");
		expect(await harness().run("rules show rule-1")).toContain("Rule rule-1");
		expect(await harness().run("rules revoke rule-1")).toContain("Cancelled");
	});
});

describe("revoke reports only what it changed", () => {
	test("`Deny rules are untouched` is true of a stored deny rule", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		store.putRule(storedRule({ id: "deny-1", kind: "deny-exact", target: "/etc/shadow" }));

		const out = await harness({ script: { confirms: [true] } }).run("rules revoke rule-1");
		expect(out).toContain("Deny rules are untouched");
		expect(store.listRules().map(rule => rule.id)).toEqual(["deny-1"]);
	});

	test("`cannot be revoked here` means nothing was touched, not even a grant", async () => {
		seedCall("audit-a");
		store.putRule(storedRule({ id: "stored-1" }));
		store.putGrant(grantIn("live", resolved.paths.cwd));
		const configured = storedRule({ id: "cfg-1", createdBy: "project", source: "smart-approve.yml" });

		const h = harness({ resolvedOverrides: { rules: [configured] }, script: { confirms: [true] } });
		const out = await h.run("rules revoke cfg-1");

		expect(out).toContain("cannot be revoked here");
		expect(h.fake.confirms).toHaveLength(0);
		expect(store.listRules().map(rule => rule.id)).toEqual(["stored-1"]);
		expect(store.findGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeDefined();
	});

	test("a rule that vanished mid-command reads as already gone, never as revoked", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		// A second session revokes it between the confirmation and the write.
		const out = await harness({
			script: { confirms: [true], onConfirm: () => store.revokeRule("rule-1") },
		}).run("rules revoke rule-1");

		expect(out).toContain("Rule rule-1 was already gone.");
		expect(out).not.toContain("Revoked rule rule-1.");
	});

	test("a second revoke does not claim to have revoked anything", async () => {
		seedCall("audit-a");
		store.putRule(storedRule());
		expect(await harness({ script: { confirms: [true] } }).run("rules revoke rule-1")).toContain(
			"Revoked rule rule-1.",
		);
		expect(await harness({ script: { confirms: [true] } }).run("rules revoke rule-1")).toContain(
			"No stored rule with ID rule-1.",
		);
	});
});

describe("commands named in output can be run on the identifiers shown", () => {
	test("every subcommand the usage advertises is real", async () => {
		const usage = await harness().run("");
		for (const name of SUBCOMMANDS) {
			expect(usage).toContain(name);
			expect(await harness().run(name)).not.toContain("Unknown subcommand");
		}
	});

	test("`pending` prints an audit ID that `review` can open", async () => {
		seedCall("audit-a");
		const listed = await harness().run("pending");
		expect(listed).toContain("Inspect one with `/smart-approve review <audit-id>`.");

		const id = /^ {2}(\S+) {2}\[/m.exec(listed)?.[1];
		expect(id).toBe("audit-a");

		const reviewed = await harness().run(`review ${id}`);
		expect(reviewed).toContain("SMART APPROVE REVIEW: audit-a");
		expect(reviewed).not.toContain("No Smart Approve record");
	});

	test("`review` points at an apply-suggestion command that finds the suggestion", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files are never an agent target",
		});
		expect(await harness().run("review audit-a")).toContain(
			"Apply with `/smart-approve apply-suggestion <audit-id>`.",
		);

		const applied = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(applied).not.toContain("No live judge suggestion");
		expect(store.listRules().map(rule => rule.id)).toEqual(["suggested-audit-a"]);
	});
});

describe("review's immutability claim survives a human decision", () => {
	test("`Original verdict (immutable)` still shows the original after an override", async () => {
		seedCall("audit-a");
		const before = store.getAudit("audit-a");
		expect(before?.decision).toBe("escalate");

		await harness({ script: { selects: [OVERRIDE_DENY], inputs: [CHALLENGE] } }).run("override audit-a");
		expect(store.getAudit("audit-a")).toEqual(before);

		const out = await harness().run("review audit-a");
		expect(out).toContain("Original verdict (immutable)");
		expect(out).toContain("decision: escalate at stage escalation");
		expect(out).toContain("overwrites the system password database");
		// The human's decision is additional history, not a rewrite of the verdict.
		expect(out).toContain("denied by human: human denied via override");
	});
});

describe("apply-suggestion cannot overstate what it inserted", () => {
	const EXACT_TARGET = "/srv/app/build.log";

	test("an exact suggested allow reads advisory and cannot skip the judge", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "allow-exact",
			toolName: "write",
			target: EXACT_TARGET,
			rationale: "one disposable file",
		});

		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		// A suggestion carries no arguments hash and no directory, so an exact target
		// is not enough. Calling it a bypass is the misreading this label prevents.
		expect(out).toContain("advisory posture — still judged (no argumentsHash, no cwd)");
		expect(out).not.toContain("skips the judge");

		const inserted = store.listRules();
		expect(inserted[0]?.kind).toBe("allow-exact");
		expect(
			matchExactAllow(
				inserted,
				"write",
				ARGS_HASH,
				[{ kind: "path", requested: EXACT_TARGET, resolved: EXACT_TARGET, dynamic: false }],
				resolved.paths.cwd,
			),
		).toBeUndefined();
	});

	test("`never persisted` is true: no durable row mentions a live suggestion", async () => {
		seedCall("audit-a");
		recordSuggestion("audit-a", {
			kind: "deny-pattern",
			toolName: "write",
			target: "/etc/**",
			rationale: "system files are never an agent target",
		});

		expect(store.listRules()).toHaveLength(0);
		expect(store.listEvents("audit-a").some(event => event.detail.includes("/etc/**"))).toBe(false);

		// Dropping process memory is what a restart does to a suggestion.
		clearSuggestions();
		const out = await harness({ script: { confirms: [true] } }).run("apply-suggestion audit-a");
		expect(out).toContain("held in memory only and never persisted, so a restart clears them");
		expect(store.listRules()).toHaveLength(0);
	});
});

describe("grant scope text matches the grant that is minted", () => {
	/** Mirrors `PERSISTENT_GRANT_TTL_MS`, which is deliberately not exported. */
	const PERSISTENT_TTL_MS = 90 * 24 * 60 * 60_000;

	test("a session grant is single use too, so nothing may promise reuse", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const h = harness({ script: { selects: [OVERRIDE_APPROVE, SCOPE_SESSION], inputs: [CHALLENGE, "ok"] } });
		const out = await h.run("override audit-a");

		const offered = h.fake.selects.at(-1)?.options.find(option => option.label === SCOPE_SESSION)?.description;
		expect(offered).toContain("Single use");
		expect(offered).not.toContain("Reusable");
		expect(out).toContain("Single use: the first matching call consumes it.");

		// The gate admits a call by consuming the grant, whatever the scope.
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeDefined();
		expect(store.consumeGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)).toBeUndefined();
	});

	test("each scope's printed lifetime is the lifetime the grant receives", async () => {
		const timeouts = resolved.config.timeouts;
		const expected: ReadonlyArray<[string, number]> = [
			[SCOPE_ONE_TIME, timeouts.brokerArgsTtlMs],
			[SCOPE_SESSION, timeouts.pendingApprovalTtlMs],
			[SCOPE_PERSISTENT, PERSISTENT_TTL_MS],
		];

		for (const [label, ttlMs] of expected) {
			// Every harness restarts its id counter at `id-1`, and `putGrant` upserts
			// by id, so the previous iteration's row has to go first.
			store.revokeAllGrants(NOW);
			const auditId = `audit-${label.replace(/\s+/g, "-")}`;
			seedCall(auditId);
			hold(auditId);
			const h = harness({
				script: { selects: [OVERRIDE_APPROVE, label], inputs: [CHALLENGE, "ok"], confirms: [true] },
			});
			const out = await h.run(`override ${auditId}`);

			const offered = h.fake.selects.at(-1)?.options.find(option => option.label === label)?.description;
			expect(offered).toContain(formatDuration(ttlMs));
			expect(out).toContain(new Date(NOW + ttlMs).toISOString());
			expect(store.listGrants().find(grant => grant.auditId === auditId)?.expiresAt).toBe(NOW + ttlMs);
		}
	});

	test("`survives restarts` is true: a persistent grant outlives the database handle", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_PERSISTENT], inputs: [CHALLENGE, "ok"], confirms: [true] },
		}).run("override audit-a");

		const databasePath = path.join(root, "state", "state.sqlite");
		store.close();
		store = openStore(databasePath);
		expect(store.findGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, NOW)?.scope).toBe("persistent");
	});

	test("`any change invalidates it` holds for arguments, directory, and policy", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_SESSION], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");
		expect(out).toContain(
			"Any change to the arguments, the working directory, the configuration, or the policy invalidates it.",
		);

		const { policyHash } = resolved;
		const cwd = resolved.paths.cwd;
		expect(
			store.findGrant(hashArguments({ ...ARGS, content: "one byte more" }), policyHash, cwd, NOW),
		).toBeUndefined();
		expect(store.findGrant(ARGS_HASH, policyHash, "/srv/other-checkout", NOW)).toBeUndefined();
		expect(store.findGrant(ARGS_HASH, "policy-after-an-edit", cwd, NOW)).toBeUndefined();
		// The untouched triple still matches, so the three misses are not vacuous.
		expect(store.findGrant(ARGS_HASH, policyHash, cwd, NOW)).toBeDefined();
	});

	test("the printed expiry instant is the instant the grant stops working", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({ script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] } }).run(
			"override audit-a",
		);

		const expiresAt = NOW + resolved.config.timeouts.brokerArgsTtlMs;
		expect(store.findGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, expiresAt - 1)).toBeDefined();
		expect(store.findGrant(ARGS_HASH, resolved.policyHash, resolved.paths.cwd, expiresAt)).toBeUndefined();
	});

	test("declining the scope prompt grants nothing and leaves the record open", async () => {
		seedCall("audit-a");
		hold("audit-a");
		const out = await harness({
			script: { selects: [OVERRIDE_APPROVE, undefined], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");

		expect(out).toContain("No scope chosen. Nothing was granted.");
		expect(store.listGrants()).toHaveLength(0);
		expect(store.getPending("audit-a")?.state).toBe("awaiting-human");
	});
});

describe("closing an override closes it", () => {
	test("`can no longer be approved` is true after expiring", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({ script: { selects: [OVERRIDE_EXPIRE], inputs: [CHALLENGE] } }).run("override audit-a");

		const again = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");
		expect(again).toContain("already resolved (expired)");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("`the record is closed` is true after denying", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({ script: { selects: [OVERRIDE_DENY], inputs: [CHALLENGE] } }).run("override audit-a");

		const again = await harness({
			script: { selects: [OVERRIDE_APPROVE, SCOPE_ONE_TIME], inputs: [CHALLENGE, "ok"] },
		}).run("override audit-a");
		expect(again).toContain("already resolved (denied)");
		expect(store.listGrants()).toHaveLength(0);
	});

	test("`with no decision` is true of expire: no approval and no denial is recorded", async () => {
		seedCall("audit-a");
		hold("audit-a");
		await harness({ script: { selects: [OVERRIDE_EXPIRE], inputs: [CHALLENGE] } }).run("override audit-a");

		const types = store.listEvents("audit-a").map(event => event.type);
		expect(types).toContain("expired");
		expect(types).not.toContain("denied");
		expect(types).not.toContain("granted");
		expect(types).not.toContain("intent-recorded");
	});
});

describe("the unguarded warning names what is still enforced", () => {
	test("output and widget stop short of claiming nothing is screened", async () => {
		const h = harness({ script: { inputs: [CHALLENGE, "debugging a broken sandbox"] } });
		const out = await h.run("unguarded");

		expect(out).toContain("Calls OMP would run unattended are no longer judged.");
		expect(out).toContain(
			"Still enforced: deny rules, protected targets, and the pre-screen on calls OMP prompts about.",
		);
		// Both of these shipped earlier and neither was true: a deny rule, a
		// protected target, and a prompt-branch pre-screen all still block.
		expect(out).not.toContain("Nothing is being screened");

		const widget = h.fake.widgets.find(entry => entry.key === WIDGET_BYPASS)?.lines?.join("\n") ?? "";
		expect(widget).toContain("Deny rules and protected targets still block.");
		expect(widget).not.toContain("Every tool call runs without semantic screening");
	});

	test("a failed challenge repeats the no-off-switch promise, proven in package.test.ts", async () => {
		const h = harness({ script: { inputs: ["not-the-challenge"] } });
		const out = await h.run("unguarded");

		expect(out).toContain("Smart Approve stays on.");
		expect(out).toContain("There is no configuration key and no environment variable that disables it.");
		expect(h.bypass.active).toBe(false);
		// The sentence itself is proven by "no silent kill switch" in
		// test/package.test.ts: the schema walk and the env-read enumeration.
	});
});
