"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
require("./evidence-view.js");

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.hidden = true; this.attributes = {}; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; }
  set textContent(value) { this._text = value; this.children = []; }
  get textContent() { return this._text || this.children.map((item) => item.textContent || "").join(""); }
}
function fixture() {
  const elements = Object.fromEntries(["results-website", "results-website-evidence", "results-website-status"].map((id) => [id, new Element("section")]));
  return { elements, document: { getElementById: (id) => elements[id], createElement: (tag) => new Element(tag) } };
}
function descendants(node) { return [node, ...node.children.flatMap(descendants)]; }

test("shows domain-specific sources first and folds general context into a disclosure", () => {
  const { elements, document } = fixture();
  globalThis.ChainShieldEvidenceView.render({ evidence: [
    { title: "General wallet safety", category: "general_information", snippet: "Security practices." },
    { title: "About example.test", category: "domain_specific", categoryReason: "Hostname appears in source." }
  ] }, document);
  const container = elements["results-website-evidence"];
  assert.match(container.children[0].textContent, /About example.test/);
  assert.equal(container.children[1].tagName, "details");
  assert.match(container.children[1].children[0].textContent, /General or unclear context/);
  assert.match(container.children[1].textContent, /General wallet safety/);
  assert.match(container.children[0].textContent, /Hostname appears in source/);
});

test("states when no domain-specific evidence exists and safely renders malformed fields", () => {
  const { elements, document } = fixture();
  globalThis.ChainShieldEvidenceView.render({ evidence: [null, "bad", { title: "General context", category: "general_information", url: "javascript:alert(1)" }] }, document);
  const all = descendants(elements["results-website-evidence"]);
  assert.ok(all.some((node) => /No useful domain-specific/.test(node.textContent)));
  assert.ok(all.some((node) => /General security context/.test(node.textContent)));
  assert.equal(all.some((node) => node.tagName === "a" && String(node.href).startsWith("javascript:")), false);
});

test("empty or malformed evidence reports no result without implying safety", () => {
  const { elements, document } = fixture();
  globalThis.ChainShieldEvidenceView.render({ evidence: "not-an-array" }, document);
  assert.match(elements["results-website-evidence"].textContent, /No public search evidence/);
  assert.match(elements["results-website-evidence"].textContent, /does not establish/);
});
