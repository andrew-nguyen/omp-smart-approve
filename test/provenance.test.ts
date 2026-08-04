import { describe, expect, test } from "bun:test";
import type { SecretEntry } from "@oh-my-pi/pi-coding-agent/secrets";
import { classifyProvenance, createProvenanceTracker, createRedactor } from "../src/context.ts";
import type { ProvenanceSource } from "../src/contracts.ts";

const PLACEHOLDER_KEY = "k".repeat(43);
const SECRET_VALUE = "Zx91qLmVnT4hRbCyWq";
const SECRET_ENTRY: SecretEntry = { type: "plain", content: SECRET_VALUE, friendlyName: "TESTKEY" };

const inert = createRedactor([], PLACEHOLDER_KEY);
const guarded = createRedactor([SECRET_ENTRY], PLACEHOLDER_KEY);

describe("provenance classification", () => {
	const cases: Array<[string, string, ProvenanceSource]> = [
		["read", "contents of README", "local"],
		["grep", "3 matches", "local"],
		["glob", "12 files", "local"],
		["ls", "src test", "local"],
		["read", "the file mentions https://example.com/docs", "local"],
		["web_search", "5 results", "external-network"],
		["browser", "page title", "browser"],
		["mcp__linear_get_issue", "PTAPP-1", "mcp"],
		["mcp__notion_search", "page found", "mcp"],
		["task", "subagent finished", "subagent"],
		["bash", "exit 0", "local"],
		["bash", "downloaded from https://evil.example/payload", "external-network"],
		["write", "wrote 3 lines", "local"],
	];

	for (const [toolName, summary, expected] of cases) {
		test(`${toolName} with "${summary.slice(0, 24)}" is ${expected}`, () => {
			expect(classifyProvenance(toolName, summary)).toBe(expected);
		});
	}

	test("a local read stays local even when its content quotes a URL", () => {
		// Reading a file that mentions a link is not a network fetch. Getting this
		// wrong would make every code review of a README look like egress.
		expect(classifyProvenance("read", "see https://example.com")).toBe("local");
		expect(classifyProvenance("cat_file", "see https://example.com")).toBe("external-network");
	});

	test("an unknown tool with no URL in its output is not treated as network-reachable", () => {
		expect(classifyProvenance("some_custom_tool", "done")).toBe("local");
	});

	test("MCP detection is case-insensitive on the prefix", () => {
		expect(classifyProvenance("MCP__Vendor_Thing", "ok")).toBe("mcp");
	});
});

describe("trust boundary", () => {
	test("tool output is untrusted and user/assistant turns are not", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordUserMessage("please deploy");
		tracker.recordAssistantRationale("running the deploy script");
		tracker.recordToolResult({ toolName: "web_search", isError: false, summary: "5 hits", at: 10 });

		const entries = tracker.recent(10);
		expect(entries.map(entry => entry.source)).toEqual(["user", "assistant", "external-network"]);
		expect(entries.map(entry => entry.untrusted)).toEqual([false, false, true]);
	});

	test("an MCP result is provenance-labeled and marked untrusted", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordToolResult({ toolName: "mcp__vendor_fetch", isError: false, summary: "payload", at: 7 });

		const [entry] = tracker.recent(1);
		expect(entry?.source).toBe("mcp");
		expect(entry?.untrusted).toBe(true);
		expect(entry?.toolName).toBe("mcp__vendor_fetch");
		expect(entry?.at).toBe(7);
	});
});

describe("bounded ring", () => {
	test("evicts the oldest entries once the ring is full", () => {
		const tracker = createProvenanceTracker({ redactor: inert, ringSize: 3 });
		for (let i = 0; i < 5; i++) {
			tracker.recordToolResult({ toolName: "read", isError: false, summary: `entry-${i}`, at: 100 + i });
		}

		const entries = tracker.recent(50);
		expect(entries).toHaveLength(3);
		expect(entries.map(entry => entry.summary)).toEqual(["entry-2", "entry-3", "entry-4"]);
	});

	test("user and assistant turns occupy ring slots and are evicted like anything else", () => {
		const tracker = createProvenanceTracker({ redactor: inert, ringSize: 2 });
		tracker.recordUserMessage("original request");
		tracker.recordToolResult({ toolName: "read", isError: false, summary: "one", at: 1 });
		tracker.recordToolResult({ toolName: "read", isError: false, summary: "two", at: 2 });

		expect(tracker.recent(50).map(entry => entry.summary)).toEqual(["one", "two"]);
		// Eviction from the trace must not lose the intent the judge compares against.
		expect(tracker.latestUserIntent()).toBe("original request");
	});

	test("defaults to a 40-entry ring", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		for (let i = 0; i < 45; i++) {
			tracker.recordToolResult({ toolName: "read", isError: false, summary: `e${i}`, at: i });
		}

		const entries = tracker.recent(1000);
		expect(entries).toHaveLength(40);
		expect(entries[0]?.summary).toBe("e5");
		expect(entries[39]?.summary).toBe("e44");
	});

	test("recent returns the newest slice in chronological order", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		for (let i = 0; i < 6; i++) {
			tracker.recordToolResult({ toolName: "read", isError: false, summary: `e${i}`, at: i });
		}

		expect(tracker.recent(2).map(entry => entry.summary)).toEqual(["e4", "e5"]);
		expect(tracker.recent(0)).toEqual([]);
		expect(tracker.recent(-1)).toEqual([]);
	});

	test("clear drops the ring, the intent, and every rationale slot", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordUserMessage("hi");
		tracker.recordAssistantRationale("ok");
		tracker.observeInFlightRationale({ text: "streaming", fromReasoning: false });
		tracker.recordToolResult({ toolName: "read", isError: false, summary: "x", at: 1 });

		tracker.clear();
		expect(tracker.recent(10)).toEqual([]);
		expect(tracker.latestUserIntent()).toBe("");
		expect(tracker.rationaleView()).toEqual({ text: "", freshness: "none", fromReasoning: false });
	});
});

describe("summaries are bounded and never raw", () => {
	test("a large tool result is capped at 200 characters and its body is not retained", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		const body = `HEAD${"X".repeat(50_000)}TAIL`;
		tracker.recordToolResult({ toolName: "read", isError: false, summary: body, at: 1 });

		const [entry] = tracker.recent(1);
		expect(entry?.summary).toHaveLength(200);
		expect(entry?.summary.endsWith("…")).toBe(true);
		expect(JSON.stringify(tracker.recent(50))).not.toContain(body);
		expect(entry?.summary).not.toContain("TAIL");
	});

	test("a multi-line result collapses to one line", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordToolResult({ toolName: "bash", isError: false, summary: "  line one\n\n\tline two  ", at: 1 });

		expect(tracker.recent(1)[0]?.summary).toBe("line one line two");
	});

	test("a failed tool result is labeled as an error", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordToolResult({ toolName: "read", isError: true, summary: "ENOENT missing.ts", at: 1 });

		expect(tracker.recent(1)[0]?.summary).toBe("error: ENOENT missing.ts");
	});

	test("secrets are redacted out of tool summaries before they enter the ring", () => {
		const tracker = createProvenanceTracker({ redactor: guarded });
		tracker.recordToolResult({ toolName: "web_search", isError: false, summary: `key ${SECRET_VALUE}`, at: 1 });

		const summary = tracker.recent(1)[0]?.summary ?? "";
		expect(summary).not.toContain(SECRET_VALUE);
		expect(summary).toMatch(/\$\$TESTKEY_[A-Z0-9]+(?::[ULCM])?\$\$/);
	});
});

describe("user intent and assistant rationale", () => {
	test("are distinct slots, each keeping only the latest turn", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordUserMessage("first request");
		tracker.recordAssistantRationale("first rationale");
		tracker.recordUserMessage("second request");
		tracker.recordAssistantRationale("second rationale");

		expect(tracker.latestUserIntent()).toBe("second request");
		expect(tracker.rationaleView().text).toBe("second rationale");
		expect(tracker.latestUserIntent()).not.toBe(tracker.rationaleView().text);
	});

	test("are capped at 2000 characters", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordUserMessage("u".repeat(5000));
		tracker.recordAssistantRationale("a".repeat(5000));

		expect(tracker.latestUserIntent()).toHaveLength(2000);
		expect(tracker.rationaleView().text).toHaveLength(2000);
	});

	test("keep their line structure, unlike the one-line trace summaries", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordUserMessage("do this\nthen that");

		expect(tracker.latestUserIntent()).toBe("do this\nthen that");
		expect(tracker.recent(1)[0]?.summary).toBe("do this then that");
	});

	test("are redacted", () => {
		const tracker = createProvenanceTracker({ redactor: guarded });
		tracker.recordUserMessage(`use ${SECRET_VALUE} to deploy`);
		tracker.recordAssistantRationale(`deploying with ${SECRET_VALUE}`);

		expect(tracker.latestUserIntent()).not.toContain(SECRET_VALUE);
		expect(tracker.rationaleView().text).not.toContain(SECRET_VALUE);
	});

	test("the tracker exposes no way to record a judge verdict or judge prompt", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		expect(Object.keys(tracker).filter(key => /judge|verdict|history/i.test(key))).toEqual([]);
	});
});

/**
 * The host fires `tool_call` before it publishes the assistant message, so the
 * completed-turn slot is always at least one message behind the calls being
 * judged. The in-flight buffer is what closes that gap, and the freshness label
 * is what keeps the judge from being told a stale statement is a live one.
 */
describe("rationale freshness", () => {
	test("reports none until anything has been said", () => {
		const tracker = createProvenanceTracker({ redactor: inert });

		expect(tracker.rationaleView()).toEqual({ text: "", freshness: "none", fromReasoning: false });
	});

	test("a completed turn is labeled as possibly predating the call", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordAssistantRationale("checked the branch");

		expect(tracker.rationaleView()).toEqual({
			text: "checked the branch",
			freshness: "previous-turn",
			fromReasoning: false,
		});
	});

	test("the streaming turn supersedes the completed one", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordAssistantRationale("what I said last turn");
		tracker.observeInFlightRationale({ text: "auditing the staged files now", fromReasoning: false });

		expect(tracker.rationaleView()).toEqual({
			text: "auditing the staged files now",
			freshness: "current-turn",
			fromReasoning: false,
		});
	});

	test("clearing the buffer falls back to the completed turn, not to nothing", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.recordAssistantRationale("what I said last turn");
		tracker.observeInFlightRationale({ text: "streaming text", fromReasoning: false });
		tracker.observeInFlightRationale(undefined);

		expect(tracker.rationaleView().freshness).toBe("previous-turn");
		expect(tracker.rationaleView().text).toBe("what I said last turn");
	});

	test("streaming deltas grow; a re-delivered earlier snapshot cannot shrink the buffer", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.observeInFlightRationale({ text: "I'll audit", fromReasoning: false });
		tracker.observeInFlightRationale({ text: "I'll audit the staged files", fromReasoning: false });
		tracker.observeInFlightRationale({ text: "I'll audit", fromReasoning: false });

		expect(tracker.rationaleView().text).toBe("I'll audit the staged files");
	});

	test("stated prose replaces reasoning text, and never the reverse", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.observeInFlightRationale({ text: "thinking at some length about it", fromReasoning: true });
		tracker.observeInFlightRationale({ text: "auditing now", fromReasoning: false });
		expect(tracker.rationaleView()).toEqual({
			text: "auditing now",
			freshness: "current-turn",
			fromReasoning: false,
		});

		tracker.observeInFlightRationale({ text: "more reasoning, much longer than the prose", fromReasoning: true });
		expect(tracker.rationaleView().text).toBe("auditing now");
	});

	test("a reasoning-derived rationale is flagged through both slots", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.observeInFlightRationale({ text: "weighing whether to read the file", fromReasoning: true });
		expect(tracker.rationaleView().fromReasoning).toBe(true);

		tracker.observeInFlightRationale(undefined);
		tracker.recordAssistantRationale("weighing whether to read the file", { fromReasoning: true });
		expect(tracker.rationaleView()).toEqual({
			text: "weighing whether to read the file",
			freshness: "previous-turn",
			fromReasoning: true,
		});
	});

	test("an empty observation is ignored rather than treated as a retraction", () => {
		const tracker = createProvenanceTracker({ redactor: inert });
		tracker.observeInFlightRationale({ text: "auditing now", fromReasoning: false });
		tracker.observeInFlightRationale({ text: "", fromReasoning: false });

		expect(tracker.rationaleView().text).toBe("auditing now");
	});

	test("in-flight text is redacted, bounded, and kept out of the trace", () => {
		const tracker = createProvenanceTracker({ redactor: guarded });
		tracker.observeInFlightRationale({ text: `pushing with ${SECRET_VALUE} `.repeat(400), fromReasoning: false });

		const view = tracker.rationaleView();
		expect(view.text).not.toContain(SECRET_VALUE);
		expect(view.text).toHaveLength(2000);
		// The buffer is a live view of one turn, not session history.
		expect(tracker.recent(50)).toEqual([]);
	});
});
