/**
 * Fact citations must point at the fact they quote.
 *
 * `goals/smart-approve/facts.md` numbers its facts by bullet order, but the file
 * is read by line number, and the two differ by two. Four of this repository's
 * eight `fact-NN` citations were once the line number instead — including one in
 * a source comment explaining why a security check exists. A citation that lands
 * on an unrelated fact is a false statement about why the code is shaped the way
 * it is, and nothing else in the suite can see it.
 */

import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const REPO = path.resolve(import.meta.dir, "..");

/** Facts in bullet order: `FACTS[0]` is fact-01. */
const FACTS: readonly string[] = readFileSync(path.join(REPO, "goals/smart-approve/facts.md"), "utf8")
	.split("\n")
	.filter(line => line.startsWith("- "))
	.map(line => normalize(line.slice(2)));

/** Flatten comment and Markdown decoration so a quote may wrap across lines. */
function normalize(text: string): string {
	return text
		.replace(/\n\s*(?:\*|\/\/|#)?\s*/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

function citedFiles(): Array<{ path: string; text: string }> {
	const files: Array<{ path: string; text: string }> = [];
	for (const [dir, extension] of [
		["src", ".ts"],
		["docs", ".md"],
	] as const) {
		for (const name of readdirSync(path.join(REPO, dir))) {
			if (!name.endsWith(extension)) continue;
			const relative = path.join(dir, name);
			files.push({ path: relative, text: readFileSync(path.join(REPO, relative), "utf8") });
		}
	}
	return files;
}

describe("fact citations", () => {
	test("facts.md still holds exactly the 44 facts every citation is numbered against", () => {
		expect(FACTS).toHaveLength(44);
		// Bullet order is the numbering, so a reordering would silently renumber
		// every citation in the repository.
		expect(FACTS[0]).toContain("release-ready omp plugin package");
		expect(FACTS[43]).toContain("smoke check");
	});

	test("every cited fact number is within range", () => {
		for (const file of citedFiles()) {
			for (const match of file.text.matchAll(/[Ff]act[- ](\d+)/g)) {
				const cited = Number(match[1]);
				expect({ file: file.path, cited }).toEqual({ file: file.path, cited: Math.min(cited, 44) });
				expect(cited).toBeGreaterThan(0);
			}
		}
	});

	test("a quoted phrase beside a citation appears in the fact it names", () => {
		// The check that bites: quoting the fact and naming the wrong number is the
		// exact shape of the mistake this file exists to catch.
		const checked: string[] = [];
		for (const file of citedFiles()) {
			const flat = normalize(file.text);
			for (const match of flat.matchAll(/[Ff]act[- ](\d+)[^."]{0,120}"([^"]{12,})"/g)) {
				const cited = Number(match[1]);
				const quote = normalize(match[2] ?? "");
				checked.push(`${file.path}: fact-${cited}`);
				expect({ at: `${file.path} fact-${cited}`, quote, found: FACTS[cited - 1]?.includes(quote) }).toEqual({
					at: `${file.path} fact-${cited}`,
					quote,
					found: true,
				});
			}
		}
		// A refactor that drops every quoted citation would otherwise pass silently.
		expect(checked.length).toBeGreaterThanOrEqual(3);
	});

	test("the coverage table numbers its rows 01 to 44 in order", () => {
		const table = readFileSync(path.join(REPO, "docs/fact-coverage.md"), "utf8");
		const rows = [...table.matchAll(/^\| (\d{2}) \|/gm)].map(match => Number(match[1]));
		expect(rows).toEqual(FACTS.map((_, index) => index + 1));
	});
});
