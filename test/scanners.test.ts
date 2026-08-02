import { describe, expect, test } from "bun:test";
import { resolvePathTarget, scanTargets, scanValues, shannonEntropy } from "../src/policy.ts";

const CWD = "/repo/project";

// Synthetic, clearly-fake credentials. None of these are real.
const FAKE = {
	openai: `sk-${"A".repeat(32)}`,
	github: `ghp_${"B".repeat(36)}`,
	githubPat: `github_pat_${"C".repeat(60)}`,
	aws: "AKIAIOSFODNN7EXAMPLE",
	slack: `xoxb-${"0".repeat(10)}-${"0".repeat(10)}-${"a".repeat(24)}`,
	jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	google: `AIza${"D".repeat(35)}`,
	privateKey: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\n-----END RSA PRIVATE KEY-----",
};

describe("credential path shapes", () => {
	const cases: Array<[string, string]> = [
		[".env", "dotenv"],
		["config/.env.production", "dotenv"],
		["/home/dev/.ssh/id_rsa", "ssh-dir"],
		["/home/dev/.aws/credentials", "aws-credentials"],
		["certs/server.pem", "pem-key"],
		["certs/server.key", "pem-key"],
		["bundle.p12", "pem-key"],
		["/home/dev/.npmrc", "npmrc"],
		["/home/dev/.netrc", "netrc"],
		["/home/dev/.kube/config", "kube-config"],
		["/home/dev/.docker/config.json", "docker-config"],
	];

	for (const [candidate, expectedId] of cases) {
		test(`flags ${candidate} as ${expectedId}`, () => {
			const findings = scanTargets([resolvePathTarget(candidate, CWD)]);
			expect(findings.map(f => f.id)).toContain(expectedId);
		});
	}

	test("does not flag an ordinary source file", () => {
		expect(scanTargets([resolvePathTarget("src/index.ts", CWD)])).toHaveLength(0);
	});

	test("does not flag a file merely named environment.ts", () => {
		expect(scanTargets([resolvePathTarget("src/environment.ts", CWD)])).toHaveLength(0);
	});

	test("does not flag a directory that merely contains 'ssh' in its name", () => {
		expect(scanTargets([resolvePathTarget("docs/sshguide.md", CWD)])).toHaveLength(0);
	});

	test("flags a dynamic target on its literal text, since we cannot resolve it", () => {
		const findings = scanTargets([resolvePathTarget("~/.ssh/id_rsa", CWD)]);
		expect(findings.map(f => f.id)).toContain("ssh-dir");
	});

	test("never includes the matched path bytes beyond the target's own text", () => {
		const findings = scanTargets([resolvePathTarget("/home/dev/.ssh/id_rsa", CWD)]);
		for (const finding of findings) {
			expect(finding.detail).not.toContain("id_rsa");
		}
	});
});

describe("credential value shapes", () => {
	const cases: Array<[keyof typeof FAKE, string]> = [
		["openai", "openai-key"],
		["github", "github-token"],
		["githubPat", "github-pat"],
		["aws", "aws-access-key"],
		["slack", "slack-token"],
		["jwt", "jwt"],
		["google", "google-api-key"],
		["privateKey", "private-key"],
	];

	for (const [key, expectedId] of cases) {
		test(`flags a ${expectedId} literal`, () => {
			const findings = scanValues({ content: FAKE[key] });
			expect(findings.map(f => f.id)).toContain(expectedId);
		});
	}

	test("finds a credential nested deep in an object", () => {
		const findings = scanValues({ a: { b: [{ c: FAKE.openai }] } });
		expect(findings.map(f => f.id)).toContain("openai-key");
		expect(findings[0]?.detail).toContain("a.b[0].c");
	});

	test("never echoes the matched secret bytes in the finding", () => {
		const findings = scanValues({ token: FAKE.github });
		expect(findings.length).toBeGreaterThan(0);
		for (const finding of findings) {
			expect(finding.detail).not.toContain(FAKE.github);
			expect(finding.detail).not.toContain("BBBB");
		}
	});

	test("reports the key path so a human can locate it without seeing it", () => {
		const findings = scanValues({ config: { apiKey: FAKE.openai } });
		expect(findings[0]?.detail).toContain("config.apiKey");
	});

	test("does not flag ordinary prose", () => {
		expect(scanValues({ content: "This function reads the user's API key from the environment." })).toHaveLength(0);
	});

	test("does not flag a short sk- prefixed word", () => {
		expect(scanValues({ content: "sk-short" })).toHaveLength(0);
	});

	test("does not flag a normal UUID", () => {
		expect(scanValues({ id: "3f2504e0-4f89-11d3-9a0c-0305e82c3301" })).toHaveLength(0);
	});

	test("does not flag a git commit sha", () => {
		expect(scanValues({ sha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678" })).toHaveLength(0);
	});

	test("does not flag a base64 image data URI prefix", () => {
		expect(scanValues({ src: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==" })).toHaveLength(0);
	});
});

describe("entropy is a signal, not a verdict", () => {
	test("random-looking text scores high", () => {
		expect(shannonEntropy("aB3$xQ9!zL2#pW7&mK4@")).toBeGreaterThan(3.5);
	});

	test("ordinary English scores low", () => {
		expect(shannonEntropy("the quick brown fox jumps")).toBeLessThan(4.2);
	});

	test("a repeated string scores near zero", () => {
		expect(shannonEntropy("aaaaaaaaaa")).toBeCloseTo(0, 5);
	});

	test("an empty string is zero", () => {
		expect(shannonEntropy("")).toBe(0);
	});

	test("high entropy alone does not produce a credential finding, avoiding ID false positives", () => {
		// A high-entropy generated ID must not be blocked as a credential.
		const generatedId = "x7Kq2mZp9RtV4nWj8LbY3cHs6FdG1aQe";
		expect(shannonEntropy(generatedId)).toBeGreaterThan(4);
		expect(scanValues({ requestId: generatedId })).toHaveLength(0);
	});
});
