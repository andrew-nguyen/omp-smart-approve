import { describe, expect, test } from "bun:test";
import path from "node:path";
import {
	argumentSizeThreshold,
	CONFIG_FILENAME,
	ConfigError,
	computeDeadlineBudget,
	configCandidates,
	type DiscoveryPaths,
	defaultDatabasePath,
	effectiveSensitivity,
	type LoadedLayerInput,
	MAX_SELF_DEADLINE_MS,
	type PolicyDocument,
	policyCandidates,
	protectedTargets,
	resolveConfig,
	ruleSpecificity,
	smartApproveConfigSchema,
} from "../src/config.ts";

const paths: DiscoveryPaths = {
	cwd: "/repo/project",
	agentDir: "/home/dev/.omp/agent",
	home: "/home/dev",
};

const defaults = smartApproveConfigSchema.parse({});

function layer(scope: "user" | "project", filePath: string, data: unknown): LoadedLayerInput {
	return { scope, filePath, data, rawContent: JSON.stringify(data) };
}

describe("schema strictness", () => {
	test("rejects an unknown top-level key so a misspelled setting cannot weaken the gate", () => {
		const result = smartApproveConfigSchema.safeParse({ judgee: {} });
		expect(result.success).toBe(false);
	});

	test("rejects an unknown key nested inside a section", () => {
		const result = smartApproveConfigSchema.safeParse({ scope: { judgeUnknownTool: false } });
		expect(result.success).toBe(false);
	});

	test("defaults to no authorized model, so a zero-config install is not ready", () => {
		expect(defaults.judge.authorizedModels).toEqual([]);
	});

	test("defaults scope unknown tools to judged", () => {
		expect(defaults.scope.judgeUnknownTools).toBe(true);
	});

	test("rejects an invalid sensitivity value", () => {
		const result = smartApproveConfigSchema.safeParse({ sensitivity: { fallback: "off" } });
		expect(result.success).toBe(false);
	});
});

describe("deadline invariant", () => {
	test("accepts the documented 2 x 10s + 1s budget under a 28s self-deadline", () => {
		const budget = computeDeadlineBudget(defaults.timeouts);
		expect(budget.worstCaseJudgeSpendMs).toBe(21_000);
		expect(budget.effectiveDeadlineMs).toBe(28_000);
	});

	test("rejects a budget that cannot finish inside the handler cap, naming the exact fields", () => {
		let caught: ConfigError | undefined;
		try {
			computeDeadlineBudget({ ...defaults.timeouts, attempts: 3, modelTimeoutMs: 10_000 });
		} catch (err) {
			caught = err as ConfigError;
		}
		expect(caught).toBeInstanceOf(ConfigError);
		expect(caught?.fields.join(" ")).toContain("timeouts.attempts");
		expect(caught?.fields.join(" ")).toContain("31000");
	});

	test("never silently clamps an over-budget configuration into validity", () => {
		expect(() => computeDeadlineBudget({ ...defaults.timeouts, attempts: 3, modelTimeoutMs: 10_000 })).toThrow(
			ConfigError,
		);
	});

	test("rejects a self-deadline above the host margin", () => {
		expect(() =>
			computeDeadlineBudget({ ...defaults.timeouts, handlerSelfDeadlineMs: MAX_SELF_DEADLINE_MS + 1 }),
		).toThrow(ConfigError);
	});

	test("rejects brokerArgsTtl greater than pendingApprovalTtl as incoherent", () => {
		let caught: ConfigError | undefined;
		try {
			computeDeadlineBudget({
				...defaults.timeouts,
				brokerArgsTtlMs: 48 * 60 * 60_000,
				pendingApprovalTtlMs: 24 * 60 * 60_000,
			});
		} catch (err) {
			caught = err as ConfigError;
		}
		expect(caught?.fields.join(" ")).toContain("brokerArgsTtlMs");
	});

	test("validates the two TTLs independently: a short broker TTL with a long record TTL is valid", () => {
		const budget = computeDeadlineBudget({
			...defaults.timeouts,
			brokerArgsTtlMs: 60_000,
			pendingApprovalTtlMs: 24 * 60 * 60_000,
		});
		expect(budget.effectiveDeadlineMs).toBe(28_000);
	});

	test("worst-case judge spend leaves a sub-floor dialog window, so the fast path is not guaranteed", () => {
		const budget = computeDeadlineBudget(defaults.timeouts);
		// 28000 - 21000 = 7000, below the 10000 floor.
		expect(budget.worstCaseDialogWindowMs).toBe(7_000);
		expect(budget.worstCaseDialogWindowMs).toBeLessThan(defaults.timeouts.dialogFloorMs);
	});

	test("an instant judge still clears the floor, so the fast path is reachable by default", () => {
		const budget = computeDeadlineBudget(defaults.timeouts);
		expect(budget.fastPathStructurallyUnreachable).toBe(false);
		expect(budget.bestCaseDialogWindowMs).toBeGreaterThanOrEqual(defaults.timeouts.dialogFloorMs);
	});

	test("a tight self-deadline marks the fast path structurally unreachable", () => {
		const budget = computeDeadlineBudget({
			...defaults.timeouts,
			handlerSelfDeadlineMs: 9_000,
			attempts: 1,
			modelTimeoutMs: 5_000,
		});
		// 9000 - 1000 cleanup = 8000 best case, below the 10000 floor.
		expect(budget.bestCaseDialogWindowMs).toBe(8_000);
		expect(budget.fastPathStructurallyUnreachable).toBe(true);
	});

	test("rejects a dialog floor above the dialog cap", () => {
		expect(() => computeDeadlineBudget({ ...defaults.timeouts, dialogFloorMs: 30_000 })).toThrow(ConfigError);
	});
});

describe("layer precedence", () => {
	test("zero config fails closed and names the setup command", () => {
		const resolved = resolveConfig([], [], paths);
		expect(resolved.ready).toBe(false);
		expect(resolved.notReadyReason).toContain("/smart-approve setup");
	});

	test("a project layer overrides a user layer for the same key", () => {
		const resolved = resolveConfig(
			[
				layer("user", "/home/dev/.omp/agent/smart-approve.yml", {
					judge: { authorizedModels: ["anthropic/haiku"] },
					sensitivity: { fallback: "permissive" },
				}),
				layer("project", "/repo/project/.omp/smart-approve.yml", {
					sensitivity: { fallback: "strict" },
				}),
			],
			[],
			paths,
		);
		expect(resolved.config.sensitivity.fallback).toBe("strict");
		expect(resolved.config.judge.authorizedModels).toEqual(["anthropic/haiku"]);
		expect(resolved.ready).toBe(true);
	});

	test("a nearer layer overrides only the rule IDs it explicitly redefines", () => {
		const resolved = resolveConfig(
			[
				layer("user", "/u.yml", {
					rules: [
						{ id: "no-env", kind: "deny-pattern", tool: "read", target: "**/.env*", reason: "secrets" },
						{ id: "no-ssh", kind: "deny-pattern", tool: "read", target: "~/.ssh/**", reason: "keys" },
					],
				}),
				layer("project", "/p.yml", {
					rules: [{ id: "no-env", kind: "deny-exact", tool: "read", target: ".env", reason: "tighter" }],
				}),
			],
			[],
			paths,
		);
		const byId = new Map(resolved.rules.map(r => [r.id, r]));
		expect(byId.get("no-env")?.kind).toBe("deny-exact");
		expect(byId.get("no-env")?.reason).toBe("tighter");
		// The user rule the project never mentioned survives.
		expect(byId.get("no-ssh")?.target).toBe("~/.ssh/**");
	});

	test("records a precedence trace and per-layer content hashes", () => {
		const resolved = resolveConfig([layer("user", "/u.yml", { judge: { authorizedModels: ["a/b"] } })], [], paths);
		expect(resolved.trace[0]).toBe("builtin defaults");
		expect(resolved.trace).toContain("user: /u.yml");
		expect(resolved.layers[0]?.contentHash).toMatch(/^[0-9a-f]{64}$/);
	});

	test("an unknown key in a discovered file throws naming the file and field", () => {
		let caught: ConfigError | undefined;
		try {
			resolveConfig([layer("project", "/p.yml", { judge: { authorisedModels: [] } })], [], paths);
		} catch (err) {
			caught = err as ConfigError;
		}
		expect(caught).toBeInstanceOf(ConfigError);
		expect(caught?.sourcePath).toBe("/p.yml");
		expect(caught?.fields.length).toBeGreaterThan(0);
	});

	test("an over-budget timeout in a discovered file fails the whole load", () => {
		expect(() =>
			resolveConfig(
				[layer("project", "/p.yml", { timeouts: { attempts: 3, modelTimeoutMs: 20_000 } })],
				[],
				paths,
			),
		).toThrow(ConfigError);
	});
});

describe("policy hash", () => {
	const doc: PolicyDocument = {
		filePath: "/repo/project/SMART_APPROVE.md",
		scope: "project",
		content: "Never deploy to production.",
		contentHash: "a".repeat(64),
	};

	test("is stable for identical inputs", () => {
		const a = resolveConfig([], [doc], paths);
		const b = resolveConfig([], [doc], paths);
		expect(a.policyHash).toBe(b.policyHash);
	});

	test("changes when a policy document changes", () => {
		const a = resolveConfig([], [doc], paths);
		const b = resolveConfig([], [{ ...doc, contentHash: "b".repeat(64) }], paths);
		expect(a.policyHash).not.toBe(b.policyHash);
	});

	test("changes when a rule changes, so outstanding grants are invalidated", () => {
		const a = resolveConfig([layer("user", "/u.yml", { rules: [] })], [], paths);
		const b = resolveConfig(
			[layer("user", "/u.yml", { rules: [{ id: "x", kind: "deny-exact", tool: "bash", target: "rm" }] })],
			[],
			paths,
		);
		expect(a.policyHash).not.toBe(b.policyHash);
	});

	test("changes when sensitivity changes", () => {
		const a = resolveConfig([layer("user", "/u.yml", { sensitivity: { fallback: "balanced" } })], [], paths);
		const b = resolveConfig([layer("user", "/u.yml", { sensitivity: { fallback: "strict" } })], [], paths);
		expect(a.policyHash).not.toBe(b.policyHash);
	});
});

describe("protected surfaces", () => {
	const db = defaultDatabasePath(paths.agentDir);
	const targets = protectedTargets(paths, db);

	test("protects the plugin's own config in both user and project scope", () => {
		expect(targets).toContain(path.join(paths.agentDir, CONFIG_FILENAME));
		expect(targets).toContain(path.join(paths.cwd, ".omp", CONFIG_FILENAME));
	});

	test("protects natural-language policy files", () => {
		expect(targets).toContain(path.join(paths.cwd, "SMART_APPROVE.md"));
		expect(targets).toContain(path.join(paths.cwd, ".omp", "SMART_APPROVE.md"));
	});

	test("protects the audit database and its WAL sidecars", () => {
		expect(targets).toContain(db);
		expect(targets).toContain(`${db}-wal`);
		expect(targets).toContain(`${db}-shm`);
	});

	test("protects OMP's own safety-relevant configuration", () => {
		expect(targets).toContain(path.join(paths.agentDir, "settings.yml"));
		expect(targets).toContain(path.join(paths.agentDir, "secrets.yml"));
		expect(targets).toContain(path.join(paths.cwd, ".omp", "secrets.yml"));
	});

	test("stores every target as an absolute normalized path", () => {
		for (const target of targets) {
			expect(path.isAbsolute(target)).toBe(true);
			expect(target).toBe(path.normalize(target));
			expect(target).not.toContain("..");
		}
	});

	test("honors a configured database path override", () => {
		const resolved = resolveConfig(
			[layer("user", "/u.yml", { audit: { databasePath: "/custom/state.sqlite" } })],
			[],
			paths,
		);
		expect(resolved.databasePath).toBe("/custom/state.sqlite");
		expect(resolved.protectedTargets).toContain("/custom/state.sqlite");
	});
});

describe("discovery order", () => {
	test("config candidates run user first so project wins", () => {
		const candidates = configCandidates(paths);
		expect(candidates[0]?.scope).toBe("user");
		expect(candidates.at(-1)?.scope).toBe("project");
	});

	test("policy candidates run broadest to most specific", () => {
		const candidates = policyCandidates(paths).map(c => c.filePath);
		const rootIndex = candidates.indexOf(path.join("/repo", "SMART_APPROVE.md"));
		const leafIndex = candidates.indexOf(path.join("/repo/project", "SMART_APPROVE.md"));
		expect(rootIndex).toBeGreaterThanOrEqual(0);
		expect(leafIndex).toBeGreaterThan(rootIndex);
	});

	test("never picks up a stray policy file in the home directory itself", () => {
		const candidates = policyCandidates({
			cwd: "/home/dev/work",
			agentDir: "/home/dev/.omp/agent",
			home: "/home/dev",
		});
		expect(candidates.map(c => c.filePath)).not.toContain("/home/dev/SMART_APPROVE.md");
	});
});

describe("warnings rather than silent degradation", () => {
	test("an unreachable fast path surfaces a warning instead of failing or degrading silently", () => {
		const resolved = resolveConfig(
			[
				layer("user", "/u.yml", {
					judge: { authorizedModels: ["a/b"] },
					timeouts: { handlerSelfDeadlineMs: 9_000, attempts: 1, modelTimeoutMs: 5_000 },
				}),
			],
			[],
			paths,
		);
		expect(resolved.ready).toBe(true);
		expect(resolved.warnings.join(" ")).toContain("can never run");
	});

	test("the default configuration warns that slow judgments resolve asynchronously", () => {
		const resolved = resolveConfig([layer("user", "/u.yml", { judge: { authorizedModels: ["a/b"] } })], [], paths);
		expect(resolved.warnings.join(" ")).toContain("asynchronously");
	});

	test("neverJudge is reported so an operator can see the exemption", () => {
		const resolved = resolveConfig([layer("user", "/u.yml", { scope: { neverJudge: ["mytool"] } })], [], paths);
		expect(resolved.warnings.join(" ")).toContain("neverJudge");
	});
});

describe("sensitivity precedence", () => {
	const config = smartApproveConfigSchema.parse({
		sensitivity: {
			fallback: "permissive",
			byTool: { bash: "balanced" },
			byRisk: { exfiltration: "strict" },
		},
	});

	test("falls back when nothing more specific matches", () => {
		expect(effectiveSensitivity(config, "read")).toBe("permissive");
	});

	test("a tool override beats the fallback", () => {
		expect(effectiveSensitivity(config, "bash")).toBe("balanced");
	});

	test("a risk override stays strict even for an otherwise permissive tool", () => {
		expect(effectiveSensitivity(config, "read", "exfiltration")).toBe("strict");
	});

	test("a risk override beats a tool override, since it is the narrower setting", () => {
		expect(effectiveSensitivity(config, "bash", "exfiltration")).toBe("strict");
	});
});

describe("argument size thresholds", () => {
	const config = smartApproveConfigSchema.parse({
		scope: { defaultArgumentSizeThreshold: 8_000, argumentSizeThresholds: { write: 2_000 } },
	});

	test("uses the per-tool override when present", () => {
		expect(argumentSizeThreshold(config, "write")).toBe(2_000);
	});

	test("falls back to the global default", () => {
		expect(argumentSizeThreshold(config, "bash")).toBe(8_000);
	});
});

describe("rule specificity", () => {
	test("exact beats patterned", () => {
		const exact = ruleSpecificity({ kind: "deny-exact", target: "/a" });
		const pattern = ruleSpecificity({ kind: "deny-pattern", target: "/a" });
		expect(exact).toBeGreaterThan(pattern);
	});

	test("deny beats allow at equal specificity", () => {
		const deny = ruleSpecificity({ kind: "deny-exact", target: "/a" });
		const allow = ruleSpecificity({ kind: "allow-exact", target: "/a" });
		expect(deny).toBeGreaterThan(allow);
	});

	test("an operation-qualified rule beats a bare one", () => {
		const withOp = ruleSpecificity({ kind: "deny-exact", target: "/a", operation: "write" });
		const without = ruleSpecificity({ kind: "deny-exact", target: "/a" });
		expect(withOp).toBeGreaterThan(without);
	});

	test("a longer literal target is narrower", () => {
		const long = ruleSpecificity({ kind: "deny-exact", target: "/very/long/specific/path/file.txt" });
		const short = ruleSpecificity({ kind: "deny-exact", target: "/a" });
		expect(long).toBeGreaterThan(short);
	});

	test("resolved rules are sorted most specific first", () => {
		const resolved = resolveConfig(
			[
				layer("user", "/u.yml", {
					rules: [
						{ id: "broad", kind: "deny-pattern", tool: "read", target: "*" },
						{ id: "narrow", kind: "deny-exact", tool: "read", target: "/etc/shadow" },
					],
				}),
			],
			[],
			paths,
		);
		expect(resolved.rules[0]?.id).toBe("narrow");
	});
});
