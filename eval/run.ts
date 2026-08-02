#!/usr/bin/env bun
/**
 * Opt-in live evaluation runner.
 *
 * Every judgment here goes through the shipped code path: the same discovery and
 * merge in `src/config.ts`, the same secret redactor and provenance tracker and
 * argument sampler in `src/context.ts`, the same allowlist model selection and
 * prompt and parser and retry loop in `src/judge.ts`. There is no eval-only
 * prompt and no eval-only leniency, because a corpus graded against a different
 * prompt measures nothing about the plugin anyone actually installs.
 *
 * Cost and blast radius: this spends real provider tokens. It is never wired
 * into CI, it never gates a release by default, and a plain run exits 0 even
 * when the judge got things wrong — the report is the product. Only `--enforce`
 * turns findings into an exit code.
 */

import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Api, Model } from "@oh-my-pi/pi-ai";
import { completeSimple } from "@oh-my-pi/pi-ai";
import { ModelRegistry } from "@oh-my-pi/pi-coding-agent/config/model-registry";
import { createExtensionModelQuery } from "@oh-my-pi/pi-coding-agent/extensibility/extensions/model-api";
import { discoverAuthStorage, Settings } from "@oh-my-pi/pi-coding-agent/sdk";
import { getAgentDir } from "@oh-my-pi/pi-utils";
import {
	argumentSizeThreshold,
	ConfigError,
	configCandidates,
	type DiscoveryPaths,
	effectiveSensitivity,
	type LoadedLayerInput,
	type PolicyDocument,
	policyCandidates,
	type ResolvedConfig,
	resolveConfig,
	type SmartApproveConfig,
} from "../src/config.ts";
import { buildArgumentsView, buildJudgeInput, createProvenanceTracker, loadSessionRedactor } from "../src/context.ts";
import type { JudgeResult, ProvenanceSource, SensitivityLevel } from "../src/contracts.ts";
import { SENSITIVITY_LEVELS } from "../src/contracts.ts";
import { createJudge, type JudgePorts, selectJudgeModel } from "../src/judge.ts";
import { canonicalize, extractTargets, hashArguments } from "../src/policy.ts";
import {
	type CaseResult,
	CorpusError,
	corpusHash,
	type EvalAggregates,
	type EvalCase,
	type EvalReport,
	evalReportSchema,
	evaluateThresholds,
	findCredentialShapes,
	isObviouslyFakeCredential,
	parseCorpus,
	REPORT_VERSION,
	type ThresholdFile,
	thresholdFileSchema,
} from "./schema.ts";

const USAGE = `omp-smart-approve live evaluation

Usage:
  bun run eval/run.ts [options]

Options:
  --model <provider/model>   Judge model to evaluate. Overrides judge.authorizedModels.
  --cases <path>             Corpus JSONL. Default: eval/cases.jsonl
  --out <dir>                Directory for report.json and report.md. Default: .artifacts/smart-approve-eval
  --sensitivity <level>      Fallback sensitivity for the run: ${SENSITIVITY_LEVELS.join(" | ")}
  --enforce <file>           YAML/JSON threshold file. Exceeding any ceiling exits nonzero.
  --help                     Print this text and exit.

This command calls a real provider and spends real tokens. It is opt-in and
non-blocking: without --enforce it exits 0 even when the judge answered badly.
Exit codes: 0 ok, 1 corpus/report/setup failure, 2 bad usage, 3 thresholds exceeded.`;

const DEFAULT_CASES = "eval/cases.jsonl";
const DEFAULT_OUT = ".artifacts/smart-approve-eval";

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

interface Flags {
	help: boolean;
	model: string | undefined;
	cases: string;
	out: string;
	sensitivity: SensitivityLevel | undefined;
	enforce: string | undefined;
}

/** Flags that consume the following argv entry. */
const VALUE_FLAGS: Record<string, true> = {
	"--model": true,
	"--cases": true,
	"--out": true,
	"--sensitivity": true,
	"--enforce": true,
};

function parseFlags(argv: readonly string[]): Flags | { error: string } {
	const flags: Flags = {
		help: false,
		model: undefined,
		cases: DEFAULT_CASES,
		out: DEFAULT_OUT,
		sensitivity: undefined,
		enforce: undefined,
	};

	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index] ?? "";
		if (arg === "--help" || arg === "-h") {
			flags.help = true;
			continue;
		}
		if (VALUE_FLAGS[arg] !== true) return { error: `unknown option "${arg}"` };

		const value = argv[index + 1];
		if (value === undefined || value.startsWith("--")) return { error: `${arg} requires a value` };
		index += 1;

		switch (arg) {
			case "--model":
				flags.model = value;
				break;
			case "--cases":
				flags.cases = value;
				break;
			case "--out":
				flags.out = value;
				break;
			case "--enforce":
				flags.enforce = value;
				break;
			default: {
				const level = SENSITIVITY_LEVELS.find(candidate => candidate === value);
				if (level === undefined) {
					return { error: `--sensitivity must be one of ${SENSITIVITY_LEVELS.join(", ")}` };
				}
				flags.sensitivity = level;
			}
		}
	}

	return flags;
}

// ---------------------------------------------------------------------------
// Configuration discovery
// ---------------------------------------------------------------------------

async function loadLayers(paths: DiscoveryPaths): Promise<LoadedLayerInput[]> {
	const layers: LoadedLayerInput[] = [];
	for (const candidate of configCandidates(paths)) {
		const file = Bun.file(candidate.filePath);
		if (!(await file.exists())) continue;
		const rawContent = await file.text();
		const data: unknown = Bun.YAML.parse(rawContent);
		layers.push({ scope: candidate.scope, filePath: candidate.filePath, data, rawContent });
	}
	return layers;
}

async function loadPolicies(paths: DiscoveryPaths): Promise<PolicyDocument[]> {
	const documents: PolicyDocument[] = [];
	for (const candidate of policyCandidates(paths)) {
		const file = Bun.file(candidate.filePath);
		if (!(await file.exists())) continue;
		const content = await file.text();
		documents.push({
			scope: candidate.scope,
			filePath: candidate.filePath,
			content,
			contentHash: createHash("sha256").update(content, "utf8").digest("hex"),
		});
	}
	return documents;
}

// ---------------------------------------------------------------------------
// Evidence replay
// ---------------------------------------------------------------------------

/**
 * Representative tool name per provenance source.
 *
 * The corpus states the source; the tracker derives it from the tool name via
 * `classifyProvenance`. Each name here round-trips to its own key, so replayed
 * evidence carries exactly the provenance the row declared instead of a second,
 * hand-maintained classification.
 */
const TOOL_BY_SOURCE: Record<ProvenanceSource, string> = {
	user: "user",
	assistant: "assistant",
	local: "read",
	"external-network": "web_fetch",
	browser: "browser",
	mcp: "mcp__eval_source",
	subagent: "task",
};

// ---------------------------------------------------------------------------
// Grading
// ---------------------------------------------------------------------------

function percentile(sortedAscending: readonly number[], p: number): number {
	if (sortedAscending.length === 0) return 0;
	const rank = Math.ceil((p / 100) * sortedAscending.length);
	const index = Math.min(sortedAscending.length - 1, Math.max(0, rank - 1));
	return sortedAscending[index] ?? 0;
}

function aggregate(results: readonly CaseResult[], byId: ReadonlyMap<string, EvalCase>): EvalAggregates {
	const latencies = results.map(result => result.latencyMs).sort((a, b) => a - b);
	let falseAllows = 0;
	let falseBlocks = 0;
	let escalations = 0;
	let parserFailures = 0;
	let timeouts = 0;
	let totalCostUsd = 0;

	for (const result of results) {
		const forbidden = byId.get(result.caseId)?.forbidden ?? [];
		if (result.decision === "allow" && forbidden.includes("allow")) falseAllows += 1;
		if (result.decision === "block" && forbidden.includes("block")) falseBlocks += 1;
		if (result.decision === "escalate") escalations += 1;
		if (result.failureKind === "parser-failure") parserFailures += 1;
		if (result.failureKind === "timeout") timeouts += 1;
		totalCostUsd += result.costUsd;
	}

	return {
		falseAllows,
		falseBlocks,
		escalations,
		parserFailures,
		timeouts,
		latencyP50: percentile(latencies, 50),
		latencyP95: percentile(latencies, 95),
		totalCostUsd,
	};
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

function renderMarkdown(report: EvalReport, byId: ReadonlyMap<string, EvalCase>): string {
	const passed = report.results.filter(result => result.passed).length;
	const lines: string[] = [
		`# Smart Approve live evaluation`,
		"",
		`- plugin: \`${report.pluginVersion}\``,
		`- judge: \`${report.provider}/${report.model}\` at \`${report.sensitivity}\` sensitivity`,
		`- corpus: \`${report.corpusHash}\``,
		`- config: \`${report.configHash}\` / policy: \`${report.policyHash}\``,
		`- window: ${new Date(report.startedAt).toISOString()} → ${new Date(report.finishedAt).toISOString()}`,
		"",
		`## Totals`,
		"",
		`| metric | value |`,
		`| --- | --- |`,
		`| cases | ${report.results.length} |`,
		`| passed | ${passed} |`,
		`| false allows | ${report.aggregates.falseAllows} |`,
		`| false blocks | ${report.aggregates.falseBlocks} |`,
		`| escalations | ${report.aggregates.escalations} |`,
		`| parser failures | ${report.aggregates.parserFailures} |`,
		`| timeouts | ${report.aggregates.timeouts} |`,
		`| latency p50 | ${Math.round(report.aggregates.latencyP50)} ms |`,
		`| latency p95 | ${Math.round(report.aggregates.latencyP95)} ms |`,
		`| total cost | $${report.aggregates.totalCostUsd.toFixed(4)} |`,
		"",
		`## Cases`,
		"",
		`| case | category | verdict | risk | latency | in/out tokens | result |`,
		`| --- | --- | --- | --- | --- | --- | --- |`,
	];

	for (const result of report.results) {
		const entry = byId.get(result.caseId);
		const outcome = result.passed ? "pass" : `FAIL (${result.failureKind ?? "unknown"})`;
		lines.push(
			`| \`${result.caseId}\` | ${entry?.category ?? "?"} | ${result.decision} | ${result.risk ?? "—"} | ` +
				`${Math.round(result.latencyMs)} ms | ${result.inputTokens}/${result.outputTokens} | ${outcome} |`,
		);
	}

	const failures = report.results.filter(result => !result.passed);
	if (failures.length > 0) {
		lines.push("", `## Failures`, "");
		for (const failure of failures) {
			const entry = byId.get(failure.caseId);
			lines.push(
				`- \`${failure.caseId}\` (${failure.failureKind ?? "unknown"}): returned \`${failure.decision}\`, ` +
					`acceptable ${(entry?.acceptable ?? []).join("/")}. ${entry?.notes ?? ""}`,
			);
		}
	}

	return `${lines.join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

async function readPluginVersion(): Promise<string> {
	const raw: unknown = await Bun.file(path.join(import.meta.dir, "..", "package.json")).json();
	if (typeof raw === "object" && raw !== null && "version" in raw && typeof raw.version === "string") {
		return raw.version;
	}
	return "unknown";
}

function describe(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

async function main(argv: readonly string[]): Promise<number> {
	const parsed = parseFlags(argv);
	if ("error" in parsed) {
		console.error(`smart-approve eval: ${parsed.error}\n`);
		console.error(USAGE);
		return 2;
	}
	// Before anything that touches disk, credentials, or the network: `--help`
	// must work on a machine that has never configured the plugin.
	if (parsed.help) {
		console.log(USAGE);
		return 0;
	}

	let cases: EvalCase[];
	try {
		cases = parseCorpus(await Bun.file(parsed.cases).text());
	} catch (error) {
		const detail = error instanceof CorpusError ? error.message : describe(error);
		console.error(`smart-approve eval: cannot read corpus ${parsed.cases}: ${detail}`);
		return 1;
	}

	// Parsed before the first provider call: a typo in the threshold file should
	// not surface after a full paid run.
	let thresholds: ThresholdFile | undefined;
	if (parsed.enforce !== undefined) {
		let raw: unknown;
		try {
			raw = Bun.YAML.parse(await Bun.file(parsed.enforce).text());
		} catch (error) {
			console.error(`smart-approve eval: cannot read threshold file ${parsed.enforce}: ${describe(error)}`);
			return 1;
		}
		const validated = thresholdFileSchema.safeParse(raw);
		if (!validated.success) {
			console.error(`smart-approve eval: invalid threshold file ${parsed.enforce}:`);
			for (const issue of validated.error.issues) {
				console.error(`  - ${issue.path.join(".") || "<root>"}: ${issue.message}`);
			}
			return 1;
		}
		thresholds = validated.data;
	}

	const cwd = process.cwd();
	const paths: DiscoveryPaths = { cwd, agentDir: getAgentDir(), home: os.homedir() };

	let resolved: ResolvedConfig;
	try {
		resolved = resolveConfig(await loadLayers(paths), await loadPolicies(paths), paths);
	} catch (error) {
		if (error instanceof ConfigError) {
			console.error(`smart-approve eval: ${error.message}`);
			for (const field of error.fields) console.error(`  - ${field}`);
			return 1;
		}
		console.error(`smart-approve eval: could not load configuration: ${describe(error)}`);
		return 1;
	}

	const base = resolved.config;
	const config: SmartApproveConfig = {
		...base,
		judge: {
			...base.judge,
			authorizedModels: parsed.model === undefined ? base.judge.authorizedModels : [parsed.model],
		},
		sensitivity: {
			...base.sensitivity,
			fallback: parsed.sensitivity ?? base.sensitivity.fallback,
		},
	};

	if (config.judge.authorizedModels.length === 0) {
		console.error(
			"smart-approve eval: no judge model is configured.\n" +
				"  Pass --model <provider/model>, or set judge.authorizedModels in\n" +
				`  ${configCandidates(paths)
					.map(candidate => candidate.filePath)
					.join(" or ")}.`,
		);
		return 1;
	}

	let ports: JudgePorts;
	try {
		const authStorage = await discoverAuthStorage(paths.agentDir);
		const registry = new ModelRegistry(authStorage);
		await registry.refresh("online-if-uncached");
		const settings = await Settings.init({ cwd, agentDir: paths.agentDir });
		// The same read-only facade OMP hands extensions as `ctx.models`, so spec
		// resolution and family comparison behave identically to a live session.
		// `current()` is undefined here: an eval run has no primary session model,
		// so contrasting-family preference has nothing to contrast against.
		const models = createExtensionModelQuery(registry, settings, () => undefined);
		ports = {
			listModels: () => models.list(),
			currentModel: () => models.current(),
			resolveModel: spec => models.resolve(spec),
			family: (model: Model<Api>) => models.family(model),
			hasConfiguredAuth: model => registry.hasConfiguredAuth(model),
			getApiKey: async (model, sessionId) => {
				const key = await registry.getApiKey(model, sessionId);
				if (key === undefined) throw new Error(`no credential resolved for ${model.provider}/${model.id}`);
				return key;
			},
			complete: (model, context, options) => completeSimple(model, context, options),
			now: () => Date.now(),
		};
	} catch (error) {
		console.error(
			`smart-approve eval: could not reach OMP's model registry: ${describe(error)}\n` +
				"  Run `omp models` to confirm this machine has a working provider setup.",
		);
		return 1;
	}

	const selection = selectJudgeModel(ports, config);
	if (!selection.ok) {
		console.error(`smart-approve eval: ${selection.failure.detail}`);
		console.error("  A live evaluation needs an authenticated provider; there is no offline mode.");
		return 1;
	}
	const judgeModel = selection.model;

	// The shipped session redactor, not a hand-rolled one: `loadSessionRedactor`
	// is `createRedactor` over OMP's three secret sources in production
	// precedence, so a corpus row is sampled and obfuscated exactly as a live call
	// would be. An eval that redacted differently would grade a different prompt.
	const redactor = await loadSessionRedactor(cwd, paths.agentDir);
	const judge = createJudge({ config, ports });
	const policyDocuments = resolved.policyDocuments.map(document => document.content);
	const postureHints = resolved.rules
		.filter(rule => rule.kind === "allow-pattern")
		.map(rule => `${rule.toolName} ${rule.target}: ${rule.reason}`);

	const byId = new Map(cases.map(entry => [entry.id, entry]));
	const results: CaseResult[] = [];
	const startedAt = Date.now();

	for (const entry of cases) {
		const toolName = entry.toolCall.toolName;
		const args = entry.toolCall.arguments;
		const extraction = extractTargets({ toolName, args, cwd });
		const threshold = argumentSizeThreshold(config, toolName);

		// One tracker per case. A shared tracker would leak the previous row's
		// evidence into this judgment, which is exactly the isolation property the
		// gate guarantees and the corpus is supposed to measure.
		const tracker = createProvenanceTracker({ redactor });
		tracker.recordUserMessage(entry.intent);
		for (const item of entry.evidence) {
			if (item.source === "user") {
				tracker.recordUserMessage(item.summary);
			} else if (item.source === "assistant") {
				tracker.recordAssistantRationale(item.summary);
			} else {
				tracker.recordToolResult({
					toolName: TOOL_BY_SOURCE[item.source],
					isError: false,
					summary: item.summary,
					at: Date.now(),
				});
			}
		}
		tracker.recordAssistantRationale(entry.primaryRationale);

		const sourceAgentId = entry.evidence.some(item => item.source === "subagent") ? "eval-subagent-1" : "eval-main";
		const view = buildArgumentsView(args, threshold, redactor);
		const input = buildJudgeInput({
			toolName,
			operation: extraction.operation,
			targets: extraction.targets,
			sourceAgentId,
			rawArguments: args,
			threshold,
			redactor,
			tracker,
			policyDocuments,
			postureHints,
			sensitivity: effectiveSensitivity(config, toolName),
		});

		// Per-case audit id derived from the literal arguments, so the judge's
		// provider-side request identity differs for every row exactly as it does
		// for every real call.
		const auditId = `eval-${entry.id}-${hashArguments(args).slice(0, 12)}`;
		const controller = new AbortController();
		const deadline = setTimeout(() => controller.abort(), resolved.budget.worstCaseJudgeSpendMs);
		let outcome: JudgeResult;
		try {
			outcome = await judge(input, controller.signal, auditId);
		} finally {
			clearTimeout(deadline);
		}

		const metrics = outcome.metrics;
		const shared = {
			caseId: entry.id,
			latencyMs: metrics.latencyMs,
			inputTokens: metrics.inputTokens ?? 0,
			outputTokens: metrics.outputTokens ?? 0,
			costUsd: metrics.costUsd ?? 0,
		};

		const record: CaseResult = outcome.ok
			? {
					...shared,
					decision: outcome.verdict.decision,
					risk: outcome.verdict.risk,
					passed: entry.acceptable.includes(outcome.verdict.decision),
					...(entry.acceptable.includes(outcome.verdict.decision)
						? {}
						: {
								failureKind:
									outcome.verdict.decision === "allow"
										? "false-allow"
										: outcome.verdict.decision === "block"
											? "false-block"
											: "forbidden-verdict",
							}),
				}
			: {
					...shared,
					decision: "error",
					risk: null,
					passed: false,
					// A judge that produced no verdict is never a pass. Which kind of
					// nothing it produced decides whether the run tripped a parser gate,
					// a deadline, or a provider fault.
					failureKind:
						outcome.failure.kind === "malformed-output" || outcome.failure.kind === "output-too-large"
							? "parser-failure"
							: outcome.failure.kind === "timeout" || outcome.failure.kind === "deadline-exhausted"
								? "timeout"
								: "judge-failure",
				};
		results.push(record);

		console.log(
			`${record.passed ? "ok  " : "FAIL"} ${entry.id.padEnd(38)} ${record.decision}` +
				`${view.incompleteCriticalContext ? " (sampled arguments)" : ""} ${Math.round(metrics.latencyMs)}ms`,
		);
	}

	const candidate: EvalReport = {
		reportVersion: REPORT_VERSION,
		pluginVersion: await readPluginVersion(),
		corpusHash: corpusHash(cases),
		configHash: createHash("sha256").update(canonicalize(config), "utf8").digest("hex"),
		policyHash: resolved.policyHash,
		model: judgeModel.id,
		provider: judgeModel.provider,
		sensitivity: config.sensitivity.fallback,
		startedAt,
		finishedAt: Date.now(),
		results,
		aggregates: aggregate(results, byId),
	};

	const validated = evalReportSchema.safeParse(candidate);
	if (!validated.success) {
		console.error("smart-approve eval: generated report failed its own schema; refusing to write it.");
		for (const issue of validated.error.issues) console.error(`  - ${issue.path.join(".")}: ${issue.message}`);
		return 1;
	}
	const report = validated.data;

	const json = `${JSON.stringify(report, null, "\t")}\n`;
	const markdown = renderMarkdown(report, byId);
	// Reports are pasted into issues and attached to release notes. Anything
	// credential-shaped that is not an obvious corpus fixture stops the write; the
	// matches themselves are never echoed, since logs are a leak channel too.
	const leaked = [...findCredentialShapes(json), ...findCredentialShapes(markdown)].filter(
		match => !isObviouslyFakeCredential(match),
	);
	if (leaked.length > 0) {
		console.error(
			`smart-approve eval: refusing to write the report — ${leaked.length} credential-shaped string(s) reached it.`,
		);
		return 1;
	}

	await mkdir(parsed.out, { recursive: true });
	const jsonPath = path.join(parsed.out, "report.json");
	const markdownPath = path.join(parsed.out, "report.md");
	await Bun.write(jsonPath, json);
	await Bun.write(markdownPath, markdown);

	const passed = report.results.filter(result => result.passed).length;
	console.log(
		`\n${passed}/${report.results.length} passed · ${report.aggregates.falseAllows} false allows · ` +
			`${report.aggregates.falseBlocks} false blocks · p95 ${Math.round(report.aggregates.latencyP95)}ms · ` +
			`$${report.aggregates.totalCostUsd.toFixed(4)}`,
	);
	console.log(`${jsonPath}\n${markdownPath}`);

	if (thresholds !== undefined) {
		const outcome = evaluateThresholds(report, thresholds);
		if (!outcome.ok) {
			console.error(`\nsmart-approve eval: --enforce thresholds exceeded`);
			for (const violation of outcome.violations) console.error(`  - ${violation}`);
			return 3;
		}
		console.log("--enforce: all thresholds satisfied");
	}

	return 0;
}

process.exit(await main(Bun.argv.slice(2)));
