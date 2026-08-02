/**
 * Package identity and distribution contract.
 *
 * A packaging mistake here is a security problem, not a cosmetic one: shipping a
 * local database, a credential file, or a test fixture inside the tarball would
 * put real data on a registry.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { z } from "zod";

const REPO = path.resolve(import.meta.dir, "..");

const packageSchema = z
	.object({
		name: z.string(),
		version: z.string(),
		license: z.string(),
		type: z.literal("module"),
		omp: z.object({ extensions: z.array(z.string()) }).strict(),
		exports: z.record(z.string(), z.string()),
		files: z.array(z.string()),
		scripts: z.record(z.string(), z.string()),
		peerDependencies: z.record(z.string(), z.string()),
		dependencies: z.record(z.string(), z.string()),
		devDependencies: z.record(z.string(), z.string()),
	})
	.passthrough();

const pkg = packageSchema.parse(JSON.parse(readFileSync(path.join(REPO, "package.json"), "utf8")));

describe("manifest", () => {
	test("declares exactly one OMP extension entry", () => {
		expect(pkg.omp.extensions).toEqual(["./src/index.ts"]);
	});

	test("the declared entry exists and needs no build step", () => {
		const entry = path.join(REPO, "src/index.ts");
		expect(readFileSync(entry, "utf8").length).toBeGreaterThan(0);
	});

	test("is ESM", () => {
		expect(pkg.type).toBe("module");
	});

	test("is MIT licensed and ships the license text", () => {
		expect(pkg.license).toBe("MIT");
		expect(readFileSync(path.join(REPO, "LICENSE"), "utf8")).toContain("MIT License");
	});

	test("pins the OMP peer range to 17.x", () => {
		expect(pkg.peerDependencies["@oh-my-pi/pi-coding-agent"]).toBe(">=17.2.2 <18");
	});

	test("keeps OMP a peer, not a runtime dependency", () => {
		expect(pkg.dependencies).not.toHaveProperty("@oh-my-pi/pi-coding-agent");
	});

	test("declares the same OMP version as a dev dependency so CI resolves it", () => {
		expect(pkg.devDependencies["@oh-my-pi/pi-coding-agent"]).toMatch(/^17\./);
	});
});

describe("scripts", () => {
	for (const name of ["check", "test", "smoke", "eval:live", "pack:check"]) {
		test(`defines a ${name} script`, () => {
			expect(pkg.scripts).toHaveProperty(name);
		});
	}

	test("ordinary CI scripts never reference a provider credential", () => {
		const ciScripts = [pkg.scripts.check, pkg.scripts.test, pkg.scripts.smoke].join(" ");
		expect(ciScripts).not.toMatch(/API_KEY|TOKEN|SECRET|ANTHROPIC|OPENAI/i);
	});

	test("live evaluation is a separate opt-in script", () => {
		expect(pkg.scripts["eval:live"]).toContain("eval/run.ts");
		expect(pkg.scripts.test).not.toContain("eval/run.ts");
	});
});

describe("runtime dependencies", () => {
	test("carries no test framework at runtime", () => {
		for (const name of Object.keys(pkg.dependencies)) {
			expect(name).not.toMatch(/vitest|jest|mocha|chai/);
		}
	});

	test("the only runtime dependency is the schema validator", () => {
		// Everything else comes from the OMP peer or from Bun's standard library.
		expect(Object.keys(pkg.dependencies)).toEqual(["zod"]);
	});
});

describe("files allowlist", () => {
	test("ships source, examples, README, and license", () => {
		expect(pkg.files).toContain("src");
		expect(pkg.files).toContain("examples");
		expect(pkg.files).toContain("README.md");
		expect(pkg.files).toContain("LICENSE");
	});

	test("does not ship tests, the eval corpus, scripts, or goal artifacts", () => {
		for (const excluded of ["test", "eval", "scripts", "goals", ".artifacts"]) {
			expect(pkg.files).not.toContain(excluded);
		}
	});
});

describe("public entry", () => {
	test("imports under Bun and exposes the named factory seam", async () => {
		const entry = await import("../src/index.ts");
		expect(typeof entry.createSmartApproveExtension).toBe("function");
	});

	test("the default export is a ready-to-register extension factory", async () => {
		const entry = await import("../src/index.ts");
		expect(typeof entry.default).toBe("function");
	});

	test("the default export constructs real dependencies, with no port injection from the environment", () => {
		const source = readFileSync(path.join(REPO, "src/index.ts"), "utf8");
		// A scripted port selectable at runtime would let an attacker disable the
		// judge through configuration. The seam is a function parameter only.
		expect(source).toContain("export default createSmartApproveExtension();");
		expect(source).not.toMatch(/Bun\.env\.[A-Z_]*(JUDGE|PORT|FAKE|MOCK|DISABLE|BYPASS)/);
		expect(source).not.toMatch(/process\.env\.[A-Z_]*(JUDGE|FAKE|MOCK|DISABLE|BYPASS)/);
	});
});

describe("no silent kill switch", () => {
	test("the config schema exposes no key that disables the plugin", async () => {
		const { smartApproveConfigSchema } = await import("../src/config.ts");
		const parsed = smartApproveConfigSchema.parse({});
		const keys = JSON.stringify(Object.keys(parsed));
		for (const forbidden of ["enabled", "disabled", "off", "bypass", "skip"]) {
			expect(keys.toLowerCase()).not.toContain(forbidden);
		}
	});

	test("no source file reads an environment variable that could disable the gate", () => {
		const sources = ["src/index.ts", "src/gate.ts", "src/policy.ts", "src/config.ts"];
		for (const relative of sources) {
			const source = readFileSync(path.join(REPO, relative), "utf8");
			expect(source).not.toMatch(/env\.\w*SMART_APPROVE\w*(DISABLE|OFF|SKIP|BYPASS)/i);
			expect(source).not.toMatch(/SMART_APPROVE_(DISABLE|OFF|SKIP|BYPASS)/i);
		}
	});
});
