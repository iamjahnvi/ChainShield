"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
require("./report.js");
require("./action-center.js");
const report = globalThis.ChainShieldReport;

test("exports investigation fields while marking real and simulated data separately", () => {
  const live = report.createReport({ url: "https://example.org", timestamp: "2026-01-01T00:00:00Z", data: { domain: "example.org", evidence: [] } });
  assert.equal(live.mode, "LIVE INVESTIGATION DATA");
  assert.equal(live.actionCenter.verdictLabel, "Inconclusive");
  const demo = report.createReport({ url: "https://example.invalid", timestamp: "2026-01-01T00:00:00Z", demo: true, data: {} });
  assert.equal(demo.mode, "SIMULATED DEMO DATA");
  assert.doesNotMatch(report.createReport({ url: "https://user:pass@example.org/?api_key=hidden&view=public", timestamp: "now", data: {} }).investigatedUrl, /hidden|user|pass/);
});

test("print report escapes attacker content and includes only safe external HTTP evidence links", () => {
  const html = report.printableHtml({ url: `https://example.org/?x="><script>alert(1)</script>`, timestamp: "now", data: { domain: "example.org", verdict: { summary: "<img src=x onerror=alert(1)>" }, evidence: [{ title: "<script>bad</script>", url: "javascript:alert(1)", snippet: "<b>raw</b>" }, { url: "https://source.example/path" }] } });
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /&lt;script&gt;bad&lt;\/script&gt;/);
  assert.match(html, /<h2>Action Center<\/h2>/);
  assert.match(html, /What to do:/);
  assert.doesNotMatch(html, /href="javascript:/);
  assert.match(html, /href="https:\/\/source\.example\/path"/);
  assert.doesNotMatch(html, /<script\b/i);
});

test("print action writes escaped report and invokes the browser print dialog", () => {
  const originalOpen = globalThis.open;
  let written = "";
  let printed = false;
  globalThis.open = () => ({ opener: {}, document: { open() {}, write(value) { written = value; }, close() {} }, focus() {}, print() { printed = true; } });
  try {
    assert.equal(report.printReport({ url: "https://example.org", timestamp: "now", data: {} }), true);
    assert.equal(printed, true);
    assert.match(written, /Use the browser's Print command/);
  } finally {
    if (originalOpen === undefined) delete globalThis.open; else globalThis.open = originalOpen;
  }
});
