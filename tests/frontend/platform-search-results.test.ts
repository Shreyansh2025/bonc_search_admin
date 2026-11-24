import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildResultFieldEntries,
  cleanFieldValue,
  formatFieldLabel,
  isWideField,
} from "../../frontend/src/lib/search-result-format.ts";
import type { PlatformFieldConfig } from "../../frontend/src/lib/search-api.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_SRC = path.resolve(__dirname, "../../frontend/src");

function makeFieldConfig(
  key: string,
  label: string,
  role: PlatformFieldConfig["role"],
): PlatformFieldConfig {
  return {
    key,
    source_column: key,
    label,
    role,
    weight: 2,
    searchable: true,
    semantic: true,
    aliases: [],
  };
}

describe("Shared Generic Search Engine Testing results formatting & CSS integrity", () => {
  it("formats field labels cleanly from engine config metadata or key fallback", () => {
    assert.equal(formatFieldLabel("title"), "Title");
    assert.equal(formatFieldLabel("job_category"), "Job Category");
    assert.equal(formatFieldLabel("document_id"), "Document ID");
    assert.equal(
      formatFieldLabel(
        "profile_text",
        makeFieldConfig("profile_text", "Profile Summary", "description"),
      ),
      "Profile Summary",
    );
  });

  it("cleans HTML tags, entities, and extra whitespace and truncates safely", () => {
    assert.equal(
      cleanFieldValue("<p>FastAPI&nbsp;&amp;&nbsp;Search&nbsp;Basics</p>"),
      "FastAPI & Search Basics",
    );
    assert.equal(cleanFieldValue("   "), "");
    assert.equal(cleanFieldValue(null), "");
    const longVal = "a".repeat(360);
    assert.equal(cleanFieldValue(longVal, 340).length, 341);
    assert.equal(cleanFieldValue(longVal, 340).endsWith("…"), true);
  });

  it("structures fields consistently across general_test, people, articles, and jobs", () => {
    const generalEntries = buildResultFieldEntries(
      {
        title: "FastAPI Search Basics",
        description: "Introduction to FastAPI hybrid search endpoints",
        content: "Detailed tutorial covering BM25F, FAISS, and RRF ranking.",
        type: "guide",
        tags: "fastapi, search, python",
        keywords: "hybrid search, api",
        location: "Indore",
      },
      undefined,
      ["title", "content"],
    );
    assert.equal(generalEntries.length, 7);
    assert.deepEqual(
      generalEntries.map((e) => e.label),
      ["Title", "Description", "Content", "Type", "Tags", "Keywords", "Location"],
    );
    assert.equal(generalEntries.find((e) => e.key === "description")?.isWide, true);
    assert.equal(generalEntries.find((e) => e.key === "content")?.isWide, true);
    assert.equal(generalEntries.find((e) => e.key === "title")?.isWide, false);
    assert.equal(generalEntries.find((e) => e.key === "title")?.isMatched, true);
    assert.equal(generalEntries.find((e) => e.key === "location")?.isMatched, false);

    const peopleEntries = buildResultFieldEntries(
      {
        full_name: "Aarav Sharma",
        profession: "Backend Engineer",
        profile_text: "Python and FastAPI specialist building search systems.",
        location: "Indore",
        empty_field: "",
      },
      [
        makeFieldConfig("full_name", "Full Name", "title"),
        makeFieldConfig("profession", "Profession", "category"),
        makeFieldConfig("profile_text", "Profile Text", "description"),
        makeFieldConfig("location", "Location", "location"),
      ],
      ["profession"],
    );
    assert.equal(peopleEntries.length, 4);
    assert.equal(peopleEntries[0].label, "Full Name");
    assert.equal(peopleEntries[2].isWide, true);

    const articleEntries = buildResultFieldEntries(
      {
        title: "Hybrid Retrieval at Scale",
        hashtags: "#search #ai",
        body: "<div>Combining BM25F &amp; FAISS vectors for accurate discovery.</div>",
        article_type: "Technical",
        author: "Editorial Team",
      },
      [
        makeFieldConfig("title", "Title", "title"),
        makeFieldConfig("hashtags", "Hashtags", "category"),
        makeFieldConfig("body", "Body", "description"),
        makeFieldConfig("article_type", "Article Type", "category"),
        makeFieldConfig("author", "Author", "general"),
      ],
      ["title", "body"],
    );
    assert.equal(articleEntries.find((e) => e.key === "body")?.value, "Combining BM25F & FAISS vectors for accurate discovery.");
    assert.equal(articleEntries.find((e) => e.key === "body")?.isWide, true);

    const jobEntries = buildResultFieldEntries(
      {
        title: "Senior Python Engineer",
        key_skills: "Python, FastAPI, SQL Server",
        job_category: "Engineering",
        description: "Build scalable APIs and search pipelines.",
        requirements: "5+ years production Python experience.",
      },
      [
        makeFieldConfig("title", "Title", "title"),
        makeFieldConfig("key_skills", "Key Skills", "skill"),
        makeFieldConfig("job_category", "Job Category", "category"),
        makeFieldConfig("description", "Description", "description"),
        makeFieldConfig("requirements", "Requirements", "description"),
      ],
      ["title", "key_skills"],
    );
    assert.equal(jobEntries.find((e) => e.key === "key_skills")?.isWide, false);
    assert.equal(jobEntries.find((e) => e.key === "requirements")?.isWide, true);
    assert.equal(isWideField("custom_note", "x".repeat(120)), true);
  });

  it("defines CSS rules for every class used in the shared search results renderer and engine testing UI", () => {
    const css = fs.readFileSync(path.join(FRONTEND_SRC, "index.css"), "utf8");
    const definedClasses = new Set<string>();
    for (const match of css.matchAll(/\.([a-zA-Z_-][a-zA-Z0-9_-]*)/g)) {
      definedClasses.add(match[1]);
    }

    const componentFiles = [
      path.join(FRONTEND_SRC, "components", "platform-search-results.tsx"),
      path.join(FRONTEND_SRC, "components", "platform-panel.tsx"),
    ];

    const missing: string[] = [];
    for (const filePath of componentFiles) {
      const content = fs.readFileSync(filePath, "utf8");
      for (const match of content.matchAll(/className\s*=\s*"([^"]+)"/g)) {
        for (const cls of match[1].split(/\s+/).filter(Boolean)) {
          if (!definedClasses.has(cls)) {
            missing.push(`${path.basename(filePath)}:.${cls}`);
          }
        }
      }
    }

    assert.deepEqual(
      missing,
      [],
      `Every CSS class used in platform-panel and platform-search-results must be defined in index.css (missing: ${missing.join(", ")})`,
    );

    // Ensure key result layout rules exist to prevent label/value or score concatenation
    for (const requiredSelector of [
      ".platform-result-item",
      ".platform-score-col",
      ".doc-fields-grid",
      ".doc-field-cell",
      ".doc-field-key",
      ".doc-field-val",
      ".signal-pills-row",
      ".term-evidence-row",
      ".query-plan-box",
      ".raw-json",
    ]) {
      assert.equal(
        css.includes(requiredSelector),
        true,
        `index.css must style ${requiredSelector}`,
      );
    }
  });
});
