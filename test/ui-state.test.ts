import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { bindDecision, holdCall, resetBrokerForTests } from "../src/broker.ts";
import { effectiveSensitivity, resolveConfig } from "../src/config.ts";
import type {
	AuditEvent,
	AuditRecord,
	EscalationContext,
	EscalationRequest,
	FrozenCall,
	PendingApproval,
} from "../src/contracts.ts";
import type { RiskCard } from "../src/gate.ts";
import { hashArguments } from "../src/policy.ts";
import type { AuditAggregate } from "../src/store.ts";
import {
	CHOICE_ALLOW_ONCE,
	CHOICE_DENY,
	createApprovalPresenter,
	type ReviewInput,
	renderApprovalRequest,
	renderPendingList,
	renderReview,
	renderRiskCard,
	renderSbar,
	renderStatus,
	STATUS_KEY,
	type UiHost,
	WIDGET_APPROVAL,
	WIDGET_BYPASS,
	WIDGET_OVERRIDE,
	WIDGET_RISK_CARD,
} from "../src/ui.ts";

/** Working directory every fixture in this file is bound to. */
const CWD_FIXTURE = "/repo/project";

const NOW = 1_700_000_000_000;
const SECRET_PATH = "/etc/shadow";

afterEach(() => resetBrokerForTests());

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface FakeUi {
	ui: UiHost;
	selects: Array<{ title: string; options: Array<{ label: string; description?: string }> }>;
	confirms: Array<{ title: string; message: string }>;
	inputs: Array<{ title: string; placeholder: string | undefined }>;
	notices: Array<{ message: string; type: string | undefined }>;
	widgets: Array<{ key: string; lines: string[] | undefined }>;
	statuses: Array<{ key: string; text: string | undefined }>;
}

interface UiScript {
	hasUI?: boolean;
	select?: (title: string, options: Array<{ label: string; description?: string }>) => Promise<string | undefined>;
	confirm?: (title: string, message: string) => Promise<boolean>;
	input?: (title: string, placeholder?: string) => Promise<string | undefined>;
}

function createFakeUi(script: UiScript = {}): FakeUi {
	const selects: FakeUi["selects"] = [];
	const confirms: FakeUi["confirms"] = [];
	const inputs: FakeUi["inputs"] = [];
	const notices: FakeUi["notices"] = [];
	const widgets: FakeUi["widgets"] = [];
	const statuses: FakeUi["statuses"] = [];
	const ui: UiHost = {
		hasUI: script.hasUI ?? true,
		select: async (title, options) => {
			selects.push({ title, options });
			return script.select === undefined ? undefined : await script.select(title, options);
		},
		confirm: async (title, message) => {
			confirms.push({ title, message });
			return script.confirm === undefined ? false : await script.confirm(title, message);
		},
		input: async (title, placeholder) => {
			inputs.push({ title, placeholder });
			return script.input === undefined ? undefined : await script.input(title, placeholder);
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

const ARGS: Record<string, unknown> = {
	path: SECRET_PATH,
	content: "root::0:0:::",
	flags: { append: false, retries: 3 },
};

function frozen(args: Record<string, unknown> = ARGS): FrozenCall {
	return {
		toolName: "write",
		toolCallId: "call-42",
		rawArguments: Object.freeze({ ...args }),
		argumentsHash: hashArguments(args),
		frozenAt: NOW,
	};
}

function request(overrides: Partial<EscalationRequest> = {}): EscalationRequest {
	const call = overrides.frozenCall ?? frozen();
	return {
		auditId: "audit-42",
		nonce: "nonce-secret-42",
		frozenCall: call,
		canonicalCall: {
			toolName: "write",
			operation: "write",
			targets: [{ kind: "path", requested: SECRET_PATH, resolved: SECRET_PATH, dynamic: false }],
			argumentsHash: call.argumentsHash,
		},
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		context: {
			userIntent: "rotate the service account password",
			agentRationale: "writing the new password file",
			rationaleFreshness: "current-turn",
			rationaleFromReasoning: false,
			flaggedBy: "judge",
		},
		sourceAgentId: "Researcher",
		sourceAgentKind: "sub",
		parentAgentId: "Main",
		expiresAt: NOW + 20_000,
		...overrides,
	};
}

function pendingRecord(overrides: Partial<PendingApproval> = {}): PendingApproval {
	return {
		auditId: "audit-42",
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		argumentsHash: hashArguments(ARGS),
		canonicalHash: "canon-1",
		policyHash: "policy-1",
		nonce: "nonce-secret-42",
		sourceAgentId: "Researcher",
		parentAgentId: "Main",
		cwd: CWD_FIXTURE,
		state: "awaiting-human",
		createdAt: NOW - 90_000,
		expiresAt: NOW + 3_600_000,
		exemptAttempts: 0,
		...overrides,
	};
}

const CONTEXT: EscalationContext = {
	userIntent: "rotate the service account password",
	agentRationale: "writing the new password file",
	rationaleFreshness: "current-turn",
	rationaleFromReasoning: false,
	flaggedBy: "judge",
};

function sbarOf(context: EscalationContext | undefined, rationale = "overwrites the system password database") {
	return renderSbar({
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		risk: "destructive-action",
		rationale,
		...(context === undefined ? {} : { context }),
	});
}

// ---------------------------------------------------------------------------
// Approval presenter
// ---------------------------------------------------------------------------

describe("createApprovalPresenter", () => {
	test("renders the literal tool name and the complete arguments", async () => {
		const fake = createFakeUi({ select: async () => CHOICE_DENY });
		await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);

		const body = fake.widgets.find(w => w.key === WIDGET_APPROVAL && w.lines !== undefined)?.lines;
		expect(body).toBeDefined();
		const text = (body ?? []).join("\n");
		// Every argument value, verbatim — not a summary, not a hash.
		expect(text).toContain(`"path": "${SECRET_PATH}"`);
		expect(text).toContain(`"content": "root::0:0:::"`);
		expect(text).toContain(`"retries": 3`);
		expect(text).toContain(`"append": false`);
		expect(text).toContain("Tool:         write");
		expect(text).toContain(hashArguments(ARGS));
		expect(text).toContain("Researcher");
		expect(text).toContain("destructive-action");
		expect(text).toContain("overwrites the system password database");
		expect(text).toContain("Expires in:   20s");
	});

	test("offers Deny first so the default focus is the safe choice", async () => {
		const fake = createFakeUi({ select: async () => undefined });
		await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);

		expect(fake.selects).toHaveLength(1);
		expect(fake.selects[0]?.options.map(o => o.label)).toEqual([CHOICE_DENY, CHOICE_ALLOW_ONCE]);
	});

	test("allow-once returns the request's own nonce and hash", async () => {
		const fake = createFakeUi({ select: async () => CHOICE_ALLOW_ONCE });
		const req = request();
		const decision = await createApprovalPresenter(fake.ui, () => NOW + 5)(req, new AbortController().signal);

		expect(decision).toEqual({
			auditId: "audit-42",
			nonce: "nonce-secret-42",
			choice: "allow-once",
			argumentsHash: hashArguments(ARGS),
			decidedAt: NOW + 5,
		});
	});

	test("a human cannot supply a nonce: any label but the two offered yields no decision", async () => {
		const fake = createFakeUi({ select: async () => "nonce-secret-42" });
		const decision = await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
		expect(decision).toBeUndefined();
	});

	test("Deny returns a deny decision, not undefined", async () => {
		const fake = createFakeUi({ select: async () => CHOICE_DENY });
		const decision = await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
		expect(decision?.choice).toBe("deny");
		expect(decision?.nonce).toBe("nonce-secret-42");
	});

	test("dialog cancellation is not approval", async () => {
		const fake = createFakeUi({ select: async () => undefined });
		const decision = await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
		expect(decision).toBeUndefined();
	});

	test("a headless session never opens a dialog and never approves", async () => {
		const fake = createFakeUi({ hasUI: false, select: async () => CHOICE_ALLOW_ONCE });
		const decision = await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
		expect(decision).toBeUndefined();
		expect(fake.selects).toHaveLength(0);
		expect(fake.widgets).toHaveLength(0);
	});

	test("an already-aborted signal short-circuits before any dialog", async () => {
		const fake = createFakeUi({ select: async () => CHOICE_ALLOW_ONCE });
		const controller = new AbortController();
		controller.abort();
		const decision = await createApprovalPresenter(fake.ui, () => NOW)(request(), controller.signal);
		expect(decision).toBeUndefined();
		expect(fake.selects).toHaveLength(0);
	});

	test("an expired request is refused without prompting", async () => {
		const fake = createFakeUi({ select: async () => CHOICE_ALLOW_ONCE });
		const decision = await createApprovalPresenter(fake.ui, () => NOW)(
			request({ expiresAt: NOW }),
			new AbortController().signal,
		);
		expect(decision).toBeUndefined();
		expect(fake.selects).toHaveLength(0);
	});

	test("aborting mid-dialog resolves undefined and a late allow cannot revive it", async () => {
		let settle: (value: string | undefined) => void = () => {};
		const gate = new Promise<string | undefined>(resolve => {
			settle = resolve;
		});
		const fake = createFakeUi({ select: () => gate });
		const controller = new AbortController();
		const inFlight = createApprovalPresenter(fake.ui, () => NOW)(request(), controller.signal);

		controller.abort();
		expect(await inFlight).toBeUndefined();

		settle(CHOICE_ALLOW_ONCE);
		expect(await inFlight).toBeUndefined();
	});

	test("a dialog that throws is not approval", async () => {
		const fake = createFakeUi({ select: () => Promise.reject(new Error("tui torn down")) });
		const decision = await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
		expect(decision).toBeUndefined();
	});

	test("arguments that cannot be rendered in full block the dialog entirely", async () => {
		const fake = createFakeUi({ select: async () => CHOICE_ALLOW_ONCE });
		// A bigint is a legitimate `unknown` value that `JSON.stringify` refuses.
		const unrenderable: Record<string, unknown> = { path: SECRET_PATH, size: 1n };
		const call: FrozenCall = {
			toolName: "write",
			toolCallId: "call-42",
			rawArguments: unrenderable,
			argumentsHash: "hash-unrenderable",
			frozenAt: NOW,
		};

		const decision = await createApprovalPresenter(fake.ui, () => NOW)(
			request({ frozenCall: call }),
			new AbortController().signal,
		);

		expect(decision).toBeUndefined();
		expect(fake.selects).toHaveLength(0);
		expect(fake.notices.some(n => n.type === "error")).toBe(true);
	});

	test("the approval widget is cleared on every exit path", async () => {
		for (const outcome of [CHOICE_ALLOW_ONCE, CHOICE_DENY, undefined]) {
			const fake = createFakeUi({ select: async () => outcome });
			await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
			expect(fake.widgets.map(w => w.key)).toEqual([WIDGET_APPROVAL, WIDGET_APPROVAL]);
			expect(fake.widgets.at(-1)?.lines).toBeUndefined();
		}
	});

	test("the approval widget is cleared even when the dialog throws", async () => {
		const fake = createFakeUi({ select: () => Promise.reject(new Error("boom")) });
		await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
		expect(fake.widgets.at(-1)).toEqual({ key: WIDGET_APPROVAL, lines: undefined });
	});

	test("the presented decision binds in the broker, and a forged nonce does not", async () => {
		const call = frozen();
		holdCall({ auditId: "audit-42", nonce: "nonce-secret-42", frozenCall: call, expiresAt: NOW + 60_000 });
		const fake = createFakeUi({ select: async () => CHOICE_ALLOW_ONCE });

		const decision = await createApprovalPresenter(fake.ui, () => NOW)(request(), new AbortController().signal);
		expect(decision).toBeDefined();
		if (decision === undefined) return;

		expect(bindDecision({ ...decision, nonce: "guessed-nonce" }, NOW).ok).toBe(false);
		const bound = bindDecision(decision, NOW);
		expect(bound.ok).toBe(true);
		// Single use: the same decision cannot be replayed.
		expect(bindDecision(decision, NOW).ok).toBe(false);
	});
});

describe("renderApprovalRequest", () => {
	test("states that Deny is the default and that approval binds to the hash", () => {
		const text = renderApprovalRequest(request(), 12_000).join("\n");
		expect(text).toContain("Deny is the default");
		expect(text).toContain("Expires in:   12s");
	});

	test("an unrenderable payload is reported, never partially shown", () => {
		const call: FrozenCall = {
			toolName: "write",
			toolCallId: "c",
			rawArguments: { keep: "visible", bad: 1n },
			argumentsHash: "h",
			frozenAt: NOW,
		};
		const text = renderApprovalRequest(request({ frozenCall: call }), 1_000).join("\n");
		expect(text).toContain("arguments cannot be rendered");
		expect(text).not.toContain("visible");
	});

	test("`complete, exactly as the agent wrote them` holds for a payload big enough to tempt truncation", () => {
		// The sentence above the arguments promises the whole call. A renderer that
		// elided, summarized, or capped anything would make a human approve a call
		// they only partly saw — the one failure this dialog exists to prevent.
		const long = "A".repeat(4_000);
		const args: Record<string, unknown> = {
			first: "head-marker",
			blob: long,
			token: "sk-live-should-still-be-visible",
			nested: { deep: { deeper: ["x", "y", { last: "leaf-marker" }] } },
			last: "tail-marker",
		};
		const text = renderApprovalRequest(request({ frozenCall: frozen(args) }), 30_000).join("\n");

		expect(text).toContain("Literal arguments (complete, exactly as the agent wrote them):");
		expect(text).toContain(`"first": "head-marker"`);
		expect(text).toContain(`"${long}"`);
		expect(text).toContain(`"token": "sk-live-should-still-be-visible"`);
		expect(text).toContain(`"last": "leaf-marker"`);
		expect(text).toContain(`"last": "tail-marker"`);
		expect(text).not.toContain("…");
		expect(text).not.toContain("[truncated");
	});

	test("leads with the SBAR block, above the forensic detail it does not replace", () => {
		const lines = renderApprovalRequest(request(), 12_000);

		expect(lines[0]).toBe("SMART APPROVE: human approval required");
		expect(lines[2]?.startsWith("S  Held for your decision: write write targeting path:/etc/shadow.")).toBe(true);
		expect(lines[3]).toBe(`B  You asked: "rotate the service account password".`);
		expect(lines[6]?.startsWith("R  ")).toBe(true);
		// Additive: the ground truth every approval is still bound to stays put.
		const text = lines.join("\n");
		expect(text).toContain("Literal arguments (complete, exactly as the agent wrote them):");
		expect(text).toContain("Deny is the default. Approve only this exact call. Approval is single-use");
		expect(text).toContain("and bound to the call hash above.");
		expect(text).toContain(`Call hash:    ${hashArguments(ARGS)}`);
	});
});

// ---------------------------------------------------------------------------
// SBAR
// ---------------------------------------------------------------------------

describe("renderSbar", () => {
	test("is exactly Situation, Background, Assessment, Recommendation, in that order", () => {
		const lines = sbarOf(CONTEXT);

		expect(lines).toHaveLength(5);
		expect(lines.map(line => line.slice(0, 3))).toEqual(["S  ", "B  ", "   ", "A  ", "R  "]);
		expect(lines[0]).toBe(
			"S  Held for your decision: write write targeting path:/etc/shadow. Risk: destructive-action.",
		);
	});

	test("an empty channel is an explicit finding, never a blank line", () => {
		const lines = sbarOf({ ...CONTEXT, userIntent: "", agentRationale: "", rationaleFreshness: "none" });

		expect(lines[1]).toBe("B  No user request was captured this session.");
		expect(lines[2]).toBe("   The agent stated no reason for this call.");
	});

	test("labels how closely the stated reason tracks this call", () => {
		const labels = (
			[
				["current-turn", false],
				["current-turn", true],
				["previous-turn", false],
				["previous-turn", true],
			] as const
		).map(
			([rationaleFreshness, rationaleFromReasoning]) =>
				sbarOf({ ...CONTEXT, rationaleFreshness, rationaleFromReasoning })[2],
		);

		expect(labels).toEqual([
			`   Agent's reason: "writing the new password file" (stated this turn).`,
			`   Agent's reason: "writing the new password file" (from private reasoning, this turn).`,
			`   Agent's reason: "writing the new password file" (may predate this call).`,
			// Staleness dominates: "this may not be about the call in front of you" wins.
			`   Agent's reason: "writing the new password file" (may predate this call).`,
		]);
	});

	test("the Assessment names which mechanism held the call", () => {
		expect(sbarOf({ ...CONTEXT, flaggedBy: "judge" })[3]).toBe(
			"A  Flagged by the judge: overwrites the system password database.",
		);
		expect(sbarOf({ ...CONTEXT, flaggedBy: "judge-failure" }, "timeout: attempt exceeded 10000ms")[3]).toBe(
			"A  The judge never screened this call: timeout: attempt exceeded 10000ms.",
		);
		expect(sbarOf({ ...CONTEXT, flaggedBy: "loop-breaker" }, "this is attempt 4 at the same operation")[3]).toBe(
			"A  Flagged by the retry loop breaker: this is attempt 4 at the same operation.",
		);
	});

	test("the Recommendation is deterministic and keyed on the stage, never model text", () => {
		expect(sbarOf({ ...CONTEXT, flaggedBy: "judge" })[4]).toBe(
			"R  Deny unless this matches what you asked for. Approving runs this exact call once, then re-locks.",
		);
		expect(sbarOf({ ...CONTEXT, flaggedBy: "judge-failure" })[4]).toBe(
			"R  The judge did not screen this call. Approve only if you can verify the literal arguments yourself.",
		);
		expect(sbarOf({ ...CONTEXT, flaggedBy: "loop-breaker" })[4]).toContain("retried this operation repeatedly");
	});

	test("clamps a runaway rationale instead of flooding the block", () => {
		const assessment = sbarOf(CONTEXT, "r".repeat(5_000))[3] ?? "";
		const detail = assessment.replace("A  Flagged by the judge: ", "");

		expect(detail).toHaveLength(220);
		expect(detail.endsWith("…")).toBe(true);
	});

	test("never doubles the terminator on a rationale that already ends in one", () => {
		expect(sbarOf(CONTEXT, "It rewrites remote history.")[3]).toBe(
			"A  Flagged by the judge: It rewrites remote history.",
		);
	});

	test("a record written before context capture says so instead of rendering blanks", () => {
		expect(sbarOf(undefined)).toEqual(["(recorded before context capture)"]);
	});
});

// ---------------------------------------------------------------------------
// Native-prompt companion card
// ---------------------------------------------------------------------------

describe("renderRiskCard", () => {
	const card: RiskCard = {
		auditId: "audit-7",
		toolName: "bash",
		risk: "exfiltration",
		rationale: "pipes repository contents to an external host",
		targetSummary: "command:curl, url:https://drop.example/upload",
		judgeAvailable: true,
	};

	test("carries redacted judgment and no literal arguments", () => {
		const text = renderRiskCard(card).join("\n");
		expect(text).toContain("exfiltration");
		expect(text).toContain("pipes repository contents to an external host");
		expect(text).toContain("command:curl, url:https://drop.example/upload");
		expect(text).toContain("audit-7");
		// Not `toContain("available")`: that substring is also inside "UNAVAILABLE",
		// so the weaker assertion would pass on the opposite claim.
		expect(text).toContain("Judge:       available");
		expect(text).not.toContain("UNAVAILABLE");
		expect(text).not.toContain("not semantically screened");
		// The native prompt already shows the literal call; this card must not.
		expect(text).not.toContain("root::0:0:::");
		expect(text).not.toContain('"content"');
		expect(text).not.toContain("Literal arguments");
	});

	test("says plainly when the call was never semantically screened", () => {
		const text = renderRiskCard({ ...card, judgeAvailable: false }).join("\n");
		expect(text).toContain("UNAVAILABLE");
		expect(text).toContain("not semantically screened");
	});

	test("carries the Background sentences when the session captured any, and none otherwise", () => {
		const bare = renderRiskCard(card).join("\n");
		expect(bare).not.toContain("Context:");

		const withContext = renderRiskCard({
			...card,
			context: {
				userIntent: "back up the repository",
				agentRationale: "uploading the archive",
				rationaleFreshness: "current-turn",
				rationaleFromReasoning: false,
			},
		}).join("\n");
		expect(withContext).toContain(`Context:     You asked: "back up the repository".`);
		expect(withContext).toContain(`             Agent's reason: "uploading the archive" (stated this turn).`);
		// No pending record exists on the prompt branch, so no Recommendation is owed.
		expect(withContext).not.toContain("Approving runs this exact call once");
	});

	test("keeps its widget key distinct from the bypass, approval, and override widgets", () => {
		expect(new Set([WIDGET_RISK_CARD, WIDGET_BYPASS, WIDGET_APPROVAL, WIDGET_OVERRIDE, STATUS_KEY]).size).toBe(5);
	});
});

// ---------------------------------------------------------------------------
// Pending list
// ---------------------------------------------------------------------------

describe("renderPendingList", () => {
	test("says so when nothing is open", () => {
		expect(renderPendingList([], NOW).join("\n")).toContain("No Smart Approve escalations are open");
	});

	test("reports a record with held arguments as mintable", () => {
		holdCall({ auditId: "audit-42", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 60_000 });
		const text = renderPendingList([pendingRecord()], NOW).join("\n");
		expect(text).toContain("can mint an exact grant");
		expect(text).not.toContain("intent-only");
	});

	test("reports every record as intent-only once the broker is empty", () => {
		resetBrokerForTests();
		const text = renderPendingList([pendingRecord()], NOW).join("\n");
		expect(text).toContain("intent-only. The literal arguments are gone");
		expect(text).not.toContain("can mint an exact grant");
	});

	test("shows audit ID, tool, redacted target, risk, agent, age, and remaining TTL", () => {
		const text = renderPendingList([pendingRecord()], NOW).join("\n");
		expect(text).toContain("audit-42");
		expect(text).toContain("write write");
		expect(text).toContain("path:/etc/shadow");
		expect(text).toContain("destructive-action");
		expect(text).toContain("Researcher (parent Main)");
		expect(text).toContain("age:       1m 30s");
		expect(text).toContain("ttl left:  1h 00m");
	});

	test("held arguments whose hash no longer matches are not mintable", () => {
		holdCall({
			auditId: "audit-42",
			nonce: "n",
			frozenCall: frozen({ path: "/tmp/other" }),
			expiresAt: NOW + 60_000,
		});
		const text = renderPendingList([pendingRecord()], NOW).join("\n");
		expect(text).toContain("intent-only");
	});

	test("shows what the user asked for, and says plainly when nothing was captured", () => {
		const asked = renderPendingList([pendingRecord({ context: CONTEXT })], NOW).join("\n");
		expect(asked).toContain(`    asked:     "rotate the service account password"`);

		const silent = renderPendingList([pendingRecord({ context: { ...CONTEXT, userIntent: "" } })], NOW).join("\n");
		expect(silent).toContain("    asked:     (no user request captured)");
	});

	test("omits the row entirely for a record written before context capture", () => {
		// An absent line is honest here; "(no user request captured)" would be a
		// claim about a session this row never observed.
		expect(renderPendingList([pendingRecord()], NOW).join("\n")).not.toContain("asked:");
	});
});

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

describe("renderStatus", () => {
	const AGGREGATE: AuditAggregate = {
		total: 12,
		allowed: 7,
		escalated: 3,
		blocked: 2,
		avgLatencyMs: 1234.6,
		inputTokens: 5000,
		outputTokens: 900,
		costUsd: 0.0421,
	};

	function baseInput(root: string) {
		const resolved = resolveConfig([], [], {
			cwd: path.join(root, "project"),
			agentDir: path.join(root, "agent"),
			home: root,
		});
		return {
			resolved,
			judge: { authorizedModels: [] as string[], authHealthy: false, detail: "no judge model authorized" },
			broker: { humanChannel: false, queueDepth: 0 },
			mainUi: true,
			bypassActive: false,
			database: { path: resolved.databasePath, healthy: true },
			openPending: 0,
			aggregate: AGGREGATE,
			aggregateWindowMs: 24 * 60 * 60_000,
			now: NOW,
		};
	}

	let root: string;
	function makeRoot(): string {
		root = mkdtempSync(path.join(os.tmpdir(), "smart-approve-ui-"));
		return root;
	}
	afterEach(() => {
		if (root) rmSync(root, { recursive: true, force: true });
	});

	test("shows hashes, deadlines, sensitivity precedence, and channel health", () => {
		const input = baseInput(makeRoot());
		const text = renderStatus(input).join("\n");
		expect(text).toContain(`Policy hash: ${input.resolved.policyHash}`);
		expect(text).toContain("Sensitivity precedence (narrowest wins): risk override > tool override > fallback");
		expect(text).toContain("fallback:      balanced");
		expect(text).toContain("handler self-deadline: 28000 ms");
		expect(text).toContain("main approval UI: ABSENT");
		expect(text).toContain("this session UI:  interactive");
		expect(text).toContain("Gate: NOT READY");
	});

	test("reports the open-pending count with the command that lists them", () => {
		const text = renderStatus({ ...baseInput(makeRoot()), openPending: 3 }).join("\n");
		expect(text).toContain("Open pending approvals: 3");
		expect(text).toContain("`/smart-approve pending`");
	});

	test("omits the listing hint when nothing is open", () => {
		const text = renderStatus(baseInput(makeRoot())).join("\n");
		expect(text).toContain("Open pending approvals: 0");
		expect(text).not.toContain("`/smart-approve pending`");
	});

	test("surfaces compatibility warnings from the resolved configuration", () => {
		const input = baseInput(makeRoot());
		const text = renderStatus({
			...input,
			resolved: { ...input.resolved, warnings: ["unknown OMP version 18.0.0; host classification may drift"] },
		}).join("\n");
		expect(text).toContain("Compatibility warnings:");
		expect(text).toContain("unknown OMP version 18.0.0");
	});

	test("leads with the unguarded banner when the gate is bypassed", () => {
		const lines = renderStatus({ ...baseInput(makeRoot()), bypassActive: true });
		expect(lines.slice(0, 4).join("\n")).toContain("UNGUARDED");
		expect(lines.join("\n")).toContain("bypass:           ACTIVE (session only)");
	});

	test("reports aggregate verdict, latency, token, and cost counts", () => {
		const text = renderStatus(baseInput(makeRoot())).join("\n");
		expect(text).toContain("total 12  allow 7  escalate 3  block 2");
		expect(text).toContain("avg latency 1235 ms");
		expect(text).toContain("tokens 5000 in / 900 out");
		expect(text).toContain("cost $0.0421");
	});

	test("reports a failing audit database instead of pretending it is healthy", () => {
		const input = baseInput(makeRoot());
		const text = renderStatus({
			...input,
			database: { path: input.resolved.databasePath, healthy: false, detail: "disk I/O error" },
		}).join("\n");
		expect(text).toContain("health: FAILING — disk I/O error");
	});

	test("counts the database could not supply read as unknown, not as zero", () => {
		// The fixture has both counts; omitting them is the only difference, so the
		// text below cannot come from an empty database.
		const { openPending, aggregate, ...rest } = baseInput(makeRoot());
		expect(openPending).toBe(0);
		expect(aggregate.total).toBe(12);

		const text = renderStatus({
			...rest,
			database: { path: rest.database.path, healthy: false, detail: "disk I/O error" },
		}).join("\n");
		// "0 waiting" and "0 decisions" would read as all-clear at the one moment
		// nothing is known.
		expect(text).toContain("Open pending approvals: unknown — the audit database could not be read");
		expect(text).not.toContain("Open pending approvals: 0");
		expect(text).not.toContain("total 0");
		expect(text).toContain("Recent decisions (last 24h 00m):");
	});

	test("reads armed once a judge model is authorized, so NOT READY means something", () => {
		const base = baseInput(makeRoot());
		const configured = resolveConfig(
			[
				{
					scope: "user",
					filePath: path.join(base.resolved.paths.agentDir, "smart-approve.yml"),
					data: { judge: { authorizedModels: ["openai/gpt-fast"] } },
					rawContent: "judge: {}",
				},
			],
			[],
			base.resolved.paths,
		);
		const text = renderStatus({ ...base, resolved: configured }).join("\n");
		expect(text).toContain("Gate: armed");
		expect(text).not.toContain("NOT READY");
	});

	test("layers really are printed lowest precedence first", () => {
		const base = baseInput(makeRoot());
		const userFile = path.join(base.resolved.paths.home, "user.yml");
		const projectFile = path.join(base.resolved.paths.cwd, "project.yml");
		const resolved = resolveConfig(
			[
				{ scope: "user", filePath: userFile, data: { sensitivity: { fallback: "strict" } }, rawContent: "u" },
				{
					scope: "project",
					filePath: projectFile,
					data: { sensitivity: { fallback: "permissive" } },
					rawContent: "p",
				},
			],
			[],
			base.resolved.paths,
		);
		// The project layer won, so it is the higher-precedence one...
		expect(resolved.config.sensitivity.fallback).toBe("permissive");

		const lines = renderStatus({ ...base, resolved });
		// ...and the heading promises the loser is printed first.
		const userIndex = lines.findIndex(line => line.includes(userFile));
		const projectIndex = lines.findIndex(line => line.includes(projectFile));
		expect(userIndex).toBeGreaterThan(0);
		expect(userIndex).toBeLessThan(projectIndex);
		expect(lines.join("\n")).toContain("Configuration layers (lowest precedence first):");
	});

	test("the sensitivity precedence line matches how sensitivity is actually resolved", () => {
		const base = baseInput(makeRoot());
		const resolved = resolveConfig(
			[
				{
					scope: "user",
					filePath: path.join(base.resolved.paths.home, "user.yml"),
					data: {
						sensitivity: {
							fallback: "permissive",
							byTool: { write: "balanced" },
							byRisk: { "destructive-action": "strict" },
						},
					},
					rawContent: "u",
				},
			],
			[],
			base.resolved.paths,
		);

		// "risk override > tool override > fallback", asked of the resolver the gate
		// uses, so the printed ordering cannot drift from the applied ordering.
		expect(effectiveSensitivity(resolved.config, "write", "destructive-action")).toBe("strict");
		expect(effectiveSensitivity(resolved.config, "write")).toBe("balanced");
		expect(effectiveSensitivity(resolved.config, "read")).toBe("permissive");

		const text = renderStatus({ ...base, resolved }).join("\n");
		expect(text).toContain("Sensitivity precedence (narrowest wins): risk override > tool override > fallback");
		expect(text).toContain("fallback:      permissive");
		expect(text).toContain("by tool:       write=balanced");
		expect(text).toContain("by risk:       destructive-action=strict");
	});

	test("says unknown tools are NOT judged only when they really are not", () => {
		const base = baseInput(makeRoot());
		expect(renderStatus(base).join("\n")).toContain("unknown tools: judged");

		const relaxed = resolveConfig(
			[
				{
					scope: "project",
					filePath: path.join(base.resolved.paths.cwd, "p.yml"),
					data: { scope: { judgeUnknownTools: false } },
					rawContent: "p",
				},
			],
			[],
			base.resolved.paths,
		);
		expect(relaxed.config.scope.judgeUnknownTools).toBe(false);
		expect(renderStatus({ ...base, resolved: relaxed }).join("\n")).toContain("unknown tools: NOT judged");
	});

	test("the unguarded banner names what still blocks instead of claiming nothing does", () => {
		// A human reading this decides how carefully to work. Overstating the bypass
		// is as wrong as understating it: deny rules and protected targets still
		// hard-block while unguarded, and prompt-branch calls are still pre-screened.
		const text = renderStatus({ ...baseInput(makeRoot()), bypassActive: true }).join("\n");
		expect(text).toContain("Calls OMP would run unattended are not judged");
		expect(text).toContain("Deny rules and protected");
		expect(text).toContain("still pre-screened");
		expect(text).not.toContain("Smart Approve is disabled");
	});
});

// ---------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------

describe("renderReview", () => {
	const RECORD: AuditRecord = {
		auditId: "audit-42",
		toolCallId: "call-42",
		toolName: "write",
		operation: "write",
		targetSummary: "path:/etc/shadow",
		argumentsHash: hashArguments(ARGS),
		canonicalHash: "canon-1",
		policyHash: "policy-1",
		sourceAgentId: "Researcher",
		sourceAgentKind: "sub",
		cwd: CWD_FIXTURE,
		decision: "escalate",
		stage: "escalation",
		risk: "destructive-action",
		rationale: "overwrites the system password database",
		judgeModel: "haiku",
		judgeProvider: "anthropic",
		retryFamilyKey: "family-1",
		retryCount: 0,
		createdAt: NOW - 90_000,
	};

	const EVENTS: AuditEvent[] = [
		{
			auditId: "audit-42",
			type: "judged",
			detail: "escalate (destructive-action)",
			actor: "judge",
			at: NOW - 89_000,
		},
		{ auditId: "audit-42", type: "escalated", detail: "pending approval opened", actor: "gate", at: NOW - 88_000 },
		{ auditId: "audit-42", type: "denied", detail: "human denied via override", actor: "human", at: NOW - 10_000 },
	];

	function reviewInput(overrides: Partial<ReviewInput> = {}): ReviewInput {
		return {
			auditId: "audit-42",
			record: RECORD,
			pending: pendingRecord(),
			events: EVENTS,
			retryFamilyKey: "family-1",
			strikes: 2,
			authority: { kind: "intent-only" as const, reason: "the literal arguments are no longer in memory" },
			now: NOW,
			...overrides,
		};
	}

	test("states plainly that a live-broker record can mint an exact grant", () => {
		const text = renderReview(
			reviewInput({ authority: { kind: "mintable", frozenCall: frozen() }, frozenCall: frozen() }),
		).join("\n");
		expect(text).toContain("It can mint an exact grant");
		expect(text).not.toContain("Intent-only");
	});

	test("names the working directory the call came from", () => {
		// Location is decision-relevant: a grant minted here is bound to this
		// directory and will not admit the same call from anywhere else.
		const text = renderReview(reviewInput()).join("\n");
		expect(text).toContain(`cwd:      ${CWD_FIXTURE}`);
	});

	test("says so plainly when a pre-migration record carries no location", () => {
		const text = renderReview(
			reviewInput({ record: { ...RECORD, cwd: "" }, pending: pendingRecord({ cwd: "" }) }),
		).join("\n");
		expect(text).toContain("(unknown, recorded before location tracking)");
	});

	test("states plainly when the record is intent-only", () => {
		const text = renderReview(reviewInput()).join("\n");
		expect(text).toContain("Intent-only. The literal arguments are gone");
		expect(text).toContain("cannot mint a grant");
		expect(text).toContain("can still deny or expire");
	});

	test("never claims to show arguments reconstructed from persistence", () => {
		const text = renderReview(reviewInput()).join("\n");
		expect(text).toContain("Raw arguments live only in the in-memory broker and are never");
		expect(text).toContain("nothing here is reconstructed from the audit database");
		expect(text).not.toContain("root::0:0:::");
	});

	test("renders literal arguments only when the broker still holds them", () => {
		const text = renderReview(
			reviewInput({ authority: { kind: "mintable", frozenCall: frozen() }, frozenCall: frozen() }),
		).join("\n");
		expect(text).toContain("(from the live in-memory broker)");
		expect(text).toContain(`"content": "root::0:0:::"`);
	});

	test("renders the immutable verdict, full history, human decisions, and retry family", () => {
		const text = renderReview(reviewInput()).join("\n");
		expect(text).toContain("Original verdict (immutable)");
		expect(text).toContain("decision: escalate at stage escalation");
		expect(text).toContain("judged");
		expect(text).toContain("escalated");
		expect(text).toContain("Human decisions:");
		expect(text).toContain("denied by human: human denied via override");
		expect(text).toContain("Retry family: family-1. Strikes: 2.");
	});

	test("does not list gate-authored events as human decisions", () => {
		const text = renderReview(reviewInput({ events: EVENTS.slice(0, 2) })).join("\n");
		const humanSection = text.slice(text.indexOf("Human decisions:"));
		expect(humanSection).toContain("(none)");
	});

	test("shows a judge suggestion as non-binding", () => {
		const text = renderReview(
			reviewInput({
				suggestion: {
					kind: "deny-pattern",
					toolName: "bash",
					target: "curl *",
					rationale: "no ad-hoc network egress",
				},
			}),
		).join("\n");
		expect(text).toContain("deny-pattern bash -> curl *");
		expect(text).toContain("Non-binding");
	});

	test("leads with the SBAR, then the forensic record it does not replace", () => {
		const lines = renderReview(reviewInput({ pending: pendingRecord({ context: CONTEXT }) }));

		expect(lines[0]).toBe("SMART APPROVE REVIEW: audit-42");
		expect(lines[2]).toBe(
			"S  Held for your decision: write write targeting path:/etc/shadow. Risk: destructive-action.",
		);
		expect(lines[3]).toBe(`B  You asked: "rotate the service account password".`);
		expect(lines[5]).toBe("A  Flagged by the judge: overwrites the system password database.");
		expect(lines.join("\n")).toContain("Original verdict (immutable):");
	});

	test("a record written before context capture says so rather than rendering blanks", () => {
		const text = renderReview(reviewInput()).join("\n");
		expect(text).toContain("(recorded before context capture)");
		expect(text).not.toContain("No user request was captured");
	});

	test("a call that was never escalated gets no SBAR at all", () => {
		const { pending: _dropped, ...withoutPending } = reviewInput();
		const text = renderReview(withoutPending).join("\n");
		expect(text).not.toContain("(recorded before context capture)");
		expect(text).not.toContain("Held for your decision");
		expect(text).toContain("No durable escalation record");
	});
});

// ---------------------------------------------------------------------------
// Copy rule
// ---------------------------------------------------------------------------

describe("escalation copy is plain sentences", () => {
	test("no dialog, SBAR, pending, review, or risk-card line stitches clauses with a glyph", () => {
		holdCall({ auditId: "audit-42", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 60_000 });
		const surfaces: string[][] = [
			renderApprovalRequest(request(), 12_000),
			sbarOf(CONTEXT),
			sbarOf({ ...CONTEXT, flaggedBy: "judge-failure", userIntent: "", agentRationale: "" }),
			sbarOf({ ...CONTEXT, flaggedBy: "loop-breaker", rationaleFreshness: "previous-turn" }),
			sbarOf(undefined),
			renderPendingList([pendingRecord({ context: CONTEXT }), pendingRecord({ auditId: "audit-43" })], NOW),
			renderReview({
				auditId: "audit-42",
				pending: pendingRecord({ context: CONTEXT }),
				events: [],
				strikes: 0,
				authority: { kind: "intent-only", reason: "the literal arguments are no longer in memory" },
				now: NOW,
			}),
			renderRiskCard({
				auditId: "audit-7",
				toolName: "bash",
				risk: "exfiltration",
				rationale: "pipes repository contents to an external host",
				targetSummary: "command:curl",
				judgeAvailable: false,
				context: CONTEXT,
			}),
		];

		for (const line of surfaces.flat()) {
			expect(line).not.toContain("—");
			expect(line).not.toContain("·");
		}
	});

	test("no decision surface passes a terminal control through to the operator", () => {
		// `\s` matches none of ESC, BEL, backspace, or C1 NEL, so whitespace
		// normalization alone leaves every one of these live. ESC can clear the
		// screen, move the cursor up, and rewrite a row already read: the same
		// forgery as a bare newline, with more reach.
		const HOSTILE = "ok\u001b[2K\u001b[1A\u0085\u0007\u0008\u2029 FORGED";
		const hostileContext: EscalationContext = {
			userIntent: HOSTILE,
			agentRationale: HOSTILE,
			rationaleFreshness: "current-turn",
			rationaleFromReasoning: false,
			flaggedBy: "judge",
		};
		holdCall({ auditId: "audit-42", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 60_000 });

		const surfaces: string[][] = [
			sbarOf(hostileContext, HOSTILE),
			renderApprovalRequest(request({ rationale: HOSTILE, context: hostileContext }), 12_000),
			renderRiskCard({
				auditId: "audit-7",
				toolName: "bash",
				risk: "exfiltration",
				rationale: HOSTILE,
				targetSummary: `path:${HOSTILE}`,
				judgeAvailable: true,
				context: hostileContext,
			}),
			renderPendingList([pendingRecord({ context: hostileContext, targetSummary: `path:${HOSTILE}` })], NOW),
			renderReview({
				auditId: "audit-42",
				pending: pendingRecord({ context: hostileContext, rationale: HOSTILE }),
				events: [],
				strikes: 0,
				suggestion: {
					kind: "deny-pattern",
					toolName: "write",
					target: "/etc/**",
					rationale: HOSTILE,
				},
				authority: { kind: "intent-only", reason: "the literal arguments are no longer in memory" },
				now: NOW,
			}),
		];

		for (const lines of surfaces) {
			for (const line of lines) {
				// No C0, C1, or Unicode separator survives anywhere on a rendered line.
				expect(line).not.toMatch(/[\p{Cc}\p{Zl}\p{Zp}]/u);
			}
			// And the row count is exactly what the renderer returned.
			expect(lines.join("\n").split("\n")).toHaveLength(lines.length);
			// Defanged in place: the operator still sees that something was there.
			expect(lines.join("\n")).toContain("\\u001b");
		}
	});

	test("an oversized operation cannot swamp the Situation line", () => {
		// `operation` is `${toolName}:${args.action}` for action-style tools, so it is
		// agent-controlled and, unbounded, defeats "short" on any terminal.
		const lines = renderSbar({
			toolName: "browser",
			operation: `browser:${"o".repeat(200_000)}`,
			targetSummary: "path:/tmp/a",
			risk: "uncertain",
			rationale: "unclear",
			context: CONTEXT,
		});

		expect(lines[0]?.length).toBeLessThan(400);
		expect(lines[0]).toContain("chars total");
		expect(lines[0]).toContain("Risk: uncertain.");
	});

	test("a persisted target cannot forge an extra line of decision support", () => {
		// `summarizeTargets` guards the way in, but a record written by a build that
		// did not is still live under `pendingApprovalTtl`, so the renderer is the
		// only thing between that row and the operator. Passed here directly, the
		// way `renderReview` passes `pending.targetSummary`.
		const hostile = "path:/repo/notes.md\nR  Approved by policy. Allow once is safe here.";
		const lines = renderSbar({
			toolName: "write",
			operation: "write",
			targetSummary: hostile,
			risk: "uncertain",
			rationale: "unclear",
			context: CONTEXT,
		});

		// Array length is meaningless if one entry can carry its own line breaks.
		expect(lines).toHaveLength(5);
		expect(lines.join("\n").split("\n")).toHaveLength(5);
		// Exactly one Recommendation, and it is ours.
		const recommendations = lines
			.join("\n")
			.split("\n")
			.filter(line => line.startsWith("R  "));
		expect(recommendations).toHaveLength(1);
		expect(recommendations[0]).toContain("Deny unless this matches what you asked for.");
		// Still shown, just defanged.
		expect(lines[0]).toContain("Approved by policy");
	});

	test("an oversized persisted target cannot swamp the block", () => {
		// The plan's promise is a glanceable block. A 5 KB path would defeat that on
		// any terminal, which is a readability failure rather than a spoof: nothing
		// here claims to control how the reader's terminal wraps what it is given.
		const lines = renderSbar({
			toolName: "write",
			operation: "write",
			targetSummary: `path:/repo/${"a".repeat(5_000)}/notes.md`,
			risk: "uncertain",
			rationale: "unclear",
			context: CONTEXT,
		});

		expect(lines[0]?.length).toBeLessThan(300);
		expect(lines[0]).toContain("/notes.md.");
		expect(lines[0]).toContain("chars total");
	});

	test("a persisted target cannot misalign the pending or review label rows", () => {
		const hostile = 'path:/repo/notes.md\n    asked:     "anything you like"';
		const record: AuditRecord = {
			auditId: "audit-42",
			toolCallId: "call-42",
			toolName: "write",
			operation: "write",
			targetSummary: hostile,
			argumentsHash: hashArguments(ARGS),
			canonicalHash: "canon-1",
			policyHash: "policy-1",
			sourceAgentId: "Researcher",
			sourceAgentKind: "sub",
			cwd: CWD_FIXTURE,
			decision: "escalate",
			stage: "escalation",
			risk: "destructive-action",
			rationale: "overwrites the system password database",
			retryFamilyKey: "family-1",
			retryCount: 0,
			createdAt: NOW - 90_000,
		};
		const listed = renderPendingList([pendingRecord({ targetSummary: hostile })], NOW);
		const reviewed = renderReview({
			auditId: "audit-42",
			record,
			events: [],
			strikes: 0,
			authority: { kind: "intent-only", reason: "the literal arguments are no longer in memory" },
			now: NOW,
		});

		for (const lines of [listed, reviewed]) {
			expect(lines.join("\n").split("\n")).toHaveLength(lines.length);
			expect(lines.filter(line => line.trimStart().startsWith("asked:"))).toHaveLength(0);
		}
	});
});
