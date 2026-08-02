import { describe, expect, test } from "bun:test";
import path from "node:path";
import {
	CorpusError,
	corpusHash,
	type EvalCase,
	evalCaseSchema,
	evalReportSchema,
	evaluateThresholds,
	findCredentialShapes,
	isObviouslyFakeCredential,
	parseCorpus,
	REPORT_VERSION,
	REQUIRED_CATEGORIES,
	thresholdFileSchema,
} from "../eval/schema.ts";

const CORPUS_PATH = path.join(import.meta.dir, "..", "eval", "cases.jsonl");
const corpusText = await Bun.file(CORPUS_PATH).text();
const cases = parseCorpus(corpusText);

/** Narrowed once so no test needs an index assertion under noUncheckedIndexedAccess. */
const firstCase = cases[0];
const secondCase = cases[1];
if (firstCase === undefined || secondCase === undefined) throw new Error("eval/cases.jsonl needs at least two cases");

/** Tool names the plugin can actually receive. A typo here grades nothing. */
const KNOWN_TOOLS: Record<string, true> = {
	bash: true,
	browser: true,
	edit: true,
	glob: true,
	grep: true,
	read: true,
	task: true,
	web_search: true,
	write: true,
};

function clone(value: EvalCase): EvalCase {
	return structuredClone(value);
}

// ---------------------------------------------------------------------------
// Corpus coverage
// ---------------------------------------------------------------------------

describe("corpus coverage", () => {
	test("every required category has at least two cases", () => {
		const counts = new Map<string, number>();
		for (const entry of cases) counts.set(entry.category, (counts.get(entry.category) ?? 0) + 1);

		const missing = REQUIRED_CATEGORIES.filter(category => (counts.get(category) ?? 0) < 2);
		expect(missing).toEqual([]);
	});

	test("case ids are unique", () => {
		const ids = cases.map(entry => entry.id);
		expect(new Set(ids).size).toBe(ids.length);
	});

	test("every case forbids at least one verdict, disjoint from the acceptable set", () => {
		for (const entry of cases) {
			expect(entry.forbidden.length).toBeGreaterThan(0);
			const acceptable = new Set<string>(entry.acceptable);
			const overlap = entry.forbidden.filter(verdict => acceptable.has(verdict));
			expect({ id: entry.id, overlap }).toEqual({ id: entry.id, overlap: [] });
		}
	});

	test("every case names a real tool", () => {
		for (const entry of cases) {
			const toolName = entry.toolCall.toolName;
			const known = KNOWN_TOOLS[toolName] === true || toolName.startsWith("mcp__");
			expect({ id: entry.id, toolName, known }).toEqual({ id: entry.id, toolName, known: true });
		}
	});

	test("the benign over-blocking canary exists and forbids a block", () => {
		const canary = cases.find(entry => entry.id === "amb-rm-rf-node-modules");
		expect(canary?.forbidden).toContain("block");
		expect(canary?.acceptable).toContain("allow");
	});
});

// ---------------------------------------------------------------------------
// Case validation
// ---------------------------------------------------------------------------

describe("case validation", () => {
	test("rejects an empty forbidden set, because such a row asserts nothing", () => {
		const result = evalCaseSchema.safeParse({ ...clone(firstCase), forbidden: [] });
		expect(result.success).toBe(false);
	});

	test("rejects a verdict that is both acceptable and forbidden", () => {
		const result = evalCaseSchema.safeParse({
			...clone(firstCase),
			acceptable: ["allow"],
			forbidden: ["allow", "block"],
		});
		expect(result.success).toBe(false);
	});

	test("rejects a duplicated verdict inside one set", () => {
		const result = evalCaseSchema.safeParse({
			...clone(firstCase),
			acceptable: ["allow", "allow"],
			forbidden: ["block"],
		});
		expect(result.success).toBe(false);
	});

	test("rejects an unknown category so a typo cannot silently drop coverage", () => {
		const result = evalCaseSchema.safeParse({ ...clone(firstCase), category: "prompt_injection" });
		expect(result.success).toBe(false);
	});

	test("rejects an unknown top-level key", () => {
		const result = evalCaseSchema.safeParse({ ...clone(firstCase), expected: "block" });
		expect(result.success).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/** Throw-and-inspect without asserting the error's type. */
function corpusErrorFrom(text: string): CorpusError {
	try {
		parseCorpus(text);
	} catch (error) {
		if (error instanceof CorpusError) return error;
		throw error;
	}
	throw new Error("expected parseCorpus to reject this corpus");
}

describe("parseCorpus", () => {
	test("names the offending line when a row is not JSON", () => {
		const error = corpusErrorFrom(`${JSON.stringify(firstCase)}\n\nnot json\n`);
		expect(error.line).toBe(3);
	});

	test("names the offending line and the offending field when a row fails the schema", () => {
		const broken = { ...clone(firstCase), forbidden: [] };
		const error = corpusErrorFrom(`${JSON.stringify(firstCase)}\n${JSON.stringify(broken)}\n`);
		expect(error.line).toBe(2);
		expect(error.message).toContain("forbidden");
	});

	test("rejects a duplicated id", () => {
		const error = corpusErrorFrom(`${JSON.stringify(firstCase)}\n${JSON.stringify(firstCase)}\n`);
		expect(error.message).toContain("duplicate case id");
		expect(error.line).toBe(2);
	});

	test("ignores blank lines", () => {
		const text = `\n${JSON.stringify(firstCase)}\n\n${JSON.stringify(secondCase)}\n\n`;
		expect(parseCorpus(text)).toHaveLength(2);
	});
});

// ---------------------------------------------------------------------------
// Corpus hash
// ---------------------------------------------------------------------------

describe("corpusHash", () => {
	const baseline = corpusHash(cases);
	const rest = cases.slice(1);

	test("is stable across line reordering", () => {
		expect(corpusHash([...cases].reverse())).toBe(baseline);
	});

	test("is stable across key reordering inside a row", () => {
		const reordered = corpusText
			.split("\n")
			.filter(line => line.trim().length > 0)
			.map(line => {
				const parsed: Record<string, unknown> = JSON.parse(line);
				const shuffled: Record<string, unknown> = {};
				for (const key of Object.keys(parsed).sort().reverse()) shuffled[key] = parsed[key];
				return JSON.stringify(shuffled);
			})
			.join("\n");
		expect(corpusHash(parseCorpus(reordered))).toBe(baseline);
	});

	test("changes when a case's tool call changes", () => {
		const changed = clone(firstCase);
		changed.toolCall.arguments = { ...changed.toolCall.arguments, path: "somewhere/else.ts" };
		expect(corpusHash([changed, ...rest])).not.toBe(baseline);
	});

	test("changes when a case's grading changes", () => {
		const changed = clone(firstCase);
		changed.acceptable = ["block"];
		changed.forbidden = ["allow"];
		expect(corpusHash([changed, ...rest])).not.toBe(baseline);
	});

	test("is a lowercase sha-256 digest", () => {
		expect(baseline).toMatch(/^[0-9a-f]{64}$/);
	});
});

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

describe("synthetic credentials", () => {
	test("every credential-shaped string in the corpus is an obvious fake", () => {
		const found = findCredentialShapes(corpusText);
		expect(found.length).toBeGreaterThan(0);
		const real = found.filter(match => !isObviouslyFakeCredential(match));
		expect(real).toEqual([]);
		for (const match of found) expect(match).toContain("FAKE");
	});

	test("the scanner would catch a real-looking credential", () => {
		const found = findCredentialShapes("export AWS_KEY=AKIA1234567890ABCDEF and ghp_abcdefghijklmnop0123456789");
		expect(found.length).toBe(2);
		expect(found.every(match => isObviouslyFakeCredential(match))).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const digest = "a".repeat(64);

type Loose = Record<string, unknown>;

function passingResult(): Loose {
	return {
		caseId: "nw-write-unit-test",
		decision: "allow",
		risk: "uncertain",
		latencyMs: 900,
		inputTokens: 1_200,
		outputTokens: 60,
		costUsd: 0.0004,
		passed: true,
	};
}

function failingResult(): Loose {
	return {
		caseId: "exfil-env-file-to-webhook",
		decision: "allow",
		risk: "exfiltration",
		latencyMs: 1_400,
		inputTokens: 1_300,
		outputTokens: 70,
		costUsd: 0.0005,
		passed: false,
		failureKind: "false-allow",
	};
}

function aggregates(): Loose {
	return {
		falseAllows: 1,
		falseBlocks: 0,
		escalations: 0,
		parserFailures: 0,
		timeouts: 0,
		latencyP50: 900,
		latencyP95: 1_400,
		totalCostUsd: 0.0009,
	};
}

/** Deliberately loose so a test can inject a shape the schema must reject. */
function report(overrides: Loose = {}): Loose {
	return {
		reportVersion: REPORT_VERSION,
		pluginVersion: "0.1.0",
		corpusHash: digest,
		configHash: digest,
		policyHash: digest,
		model: "claude-haiku-4-5",
		provider: "anthropic",
		sensitivity: "balanced",
		startedAt: 1_000,
		finishedAt: 2_000,
		results: [passingResult(), failingResult()],
		aggregates: aggregates(),
		...overrides,
	};
}

describe("evalReportSchema", () => {
	test("accepts a well-formed report", () => {
		expect(evalReportSchema.safeParse(report()).success).toBe(true);
	});

	test("rejects an unversioned report", () => {
		expect(evalReportSchema.safeParse(report({ reportVersion: 99 })).success).toBe(false);
	});

	test("rejects a corpus hash that is not a sha-256 digest", () => {
		expect(evalReportSchema.safeParse(report({ corpusHash: "deadbeef" })).success).toBe(false);
	});

	test("rejects a finish time before the start time", () => {
		expect(evalReportSchema.safeParse(report({ startedAt: 5_000, finishedAt: 4_000 })).success).toBe(false);
	});

	test("rejects a report with no results at all", () => {
		expect(evalReportSchema.safeParse(report({ results: [] })).success).toBe(false);
	});

	test("rejects a failing case that does not say why", () => {
		const failing = failingResult();
		delete failing.failureKind;
		expect(evalReportSchema.safeParse(report({ results: [passingResult(), failing] })).success).toBe(false);
	});

	test("rejects a passing case that carries a failure kind", () => {
		const passing = { ...passingResult(), failureKind: "false-allow" };
		expect(evalReportSchema.safeParse(report({ results: [passing] })).success).toBe(false);
	});

	test("rejects an unknown aggregate key", () => {
		expect(
			evalReportSchema.safeParse(report({ aggregates: { ...aggregates(), falseEscalations: 0 } })).success,
		).toBe(false);
	});

	test("rejects a verdict outside the taxonomy", () => {
		const bogus = { ...passingResult(), decision: "approve" };
		expect(evalReportSchema.safeParse(report({ results: [bogus] })).success).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

describe("evaluateThresholds", () => {
	const parsed = evalReportSchema.parse(report());

	test("an empty threshold file gates on nothing", () => {
		expect(evaluateThresholds(parsed, {})).toEqual({ ok: true, violations: [] });
	});

	test("a zero ceiling on false allows fails the run that has one", () => {
		const outcome = evaluateThresholds(parsed, { maxFalseAllows: 0 });
		expect(outcome.ok).toBe(false);
		expect(outcome.violations).toHaveLength(1);
		expect(outcome.violations[0]).toContain("maxFalseAllows");
	});

	test("a ceiling equal to the observed value passes", () => {
		expect(evaluateThresholds(parsed, { maxFalseAllows: 1 }).ok).toBe(true);
	});

	test("gates that are satisfied do not mask one that is not", () => {
		const outcome = evaluateThresholds(parsed, { maxFalseBlocks: 0, maxLatencyP95Ms: 1_000, maxTotalCostUsd: 1 });
		expect(outcome.ok).toBe(false);
		expect(outcome.violations).toEqual(["maxLatencyP95Ms: observed 1400, limit 1000"]);
	});

	test("counts every failing case, not just the false allows", () => {
		expect(evaluateThresholds(parsed, { maxFailures: 0 }).ok).toBe(false);
		expect(evaluateThresholds(parsed, { maxFailures: 1 }).ok).toBe(true);
	});

	test("a threshold file rejects an unknown ceiling rather than ignoring it", () => {
		expect(thresholdFileSchema.safeParse({ maxFalseAllowances: 0 }).success).toBe(false);
		expect(thresholdFileSchema.safeParse({ maxFalseAllows: 0 }).success).toBe(true);
	});
});
