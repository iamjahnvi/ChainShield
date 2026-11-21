const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { test } = require("node:test");

class Element {
  constructor(tag = "div") { this.tagName = tag; this.children = []; this.listeners = {}; this.hidden = false; this.value = ""; this.disabled = false; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  reset() { this.resetCalled = true; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text || this.children.map((item) => item.textContent || "").join(""); }
}

function harness(fetchImpl) {
  const ids = ["results-community", "community-status", "community-summary", "community-reports", "community-report-open", "community-report-form", "community-form-status", "community-report-submit", "community-report-cancel", "community-category", "community-description", "community-evidence-url"];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element(id.includes("form") ? "form" : "div")]));
  const document = { getElementById: (id) => elements[id], createElement: (tag) => new Element(tag) };
  const window = {};
  vm.runInNewContext(fs.readFileSync(require.resolve("./community.js"), "utf8"), { document, window, URL, fetch: fetchImpl, Date, Number, encodeURIComponent, Promise });
  return { api: window.initializeCommunityIntelligence, elements };
}

const summary = { domain: "example.com", totalApproved: 0, categoryCounts: {}, recentReports: [], source: "community_reports", trust: "unverified_user_submissions" };
const response = (body, ok = true, status = 200) => ({ ok, status, json: async () => body });

test("loads and renders the honest empty state", async () => {
  const { api, elements } = harness(async () => response(summary));
  api("example.com", "http://localhost:3000/api");
  assert.match(elements["community-status"].textContent, /Loading community reports/);
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(elements["community-status"].textContent, /0 approved community reports/i);
  assert.equal(elements["community-reports"].textContent, "No community reports yet.");
});

test("renders successful approved reports and category counts", async () => {
  const data = { ...summary, totalApproved: 1, categoryCounts: { phishing: 1 }, recentReports: [{ category: "phishing", description: "Credential capture report", evidenceUrl: "https://evidence.example/case", submittedAt: "2026-11-19T00:00:00Z" }] };
  const { api, elements } = harness(async () => response(data));
  api("example.com", "http://localhost:3000/api");
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(elements["community-summary"].textContent, /Phishing: 1/);
  assert.match(elements["community-reports"].textContent, /Credential capture report/);
  assert.match(elements["community-reports"].textContent, /not opened by ChainShield/);
});

test("renders service errors without affecting another assessment section", async () => {
  const { api, elements } = harness(async () => response({ error: "offline" }, false, 503));
  api("example.com", "http://localhost:3000/api");
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(elements["community-status"].textContent, /security assessment is unaffected/i);
  assert.match(elements["community-reports"].textContent, /offline/);
});

test("submits a report and displays its pending moderation state", async () => {
  const calls = [];
  const { api, elements } = harness(async (url, options = {}) => {
    calls.push({ url, options });
    return url.endsWith("/community/reports")
      ? response({ status: "pending", message: "Report received for moderation." }, true, 202)
      : response(summary);
  });
  api("example.com", "http://localhost:3000/api");
  elements["community-report-form"].hidden = false;
  elements["community-category"].value = "phishing";
  elements["community-description"].value = "This page tried to capture my credentials.";
  await elements["community-report-form"].listeners.submit({ preventDefault() {} });
  assert.ok(calls.find((call) => call.url.endsWith("/community/reports")));
  assert.match(elements["community-form-status"].textContent, /moderation/i);
});

test("keeps the form open and shows submission errors for retry", async () => {
  const { api, elements } = harness(async (url) => url.endsWith("/community/reports")
    ? response({ error: "Report limit reached. Try again later." }, false, 429)
    : response(summary));
  api("example.com", "http://localhost:3000/api");
  elements["community-report-form"].hidden = false;
  elements["community-category"].value = "phishing";
  elements["community-description"].value = "This page tried to capture my credentials.";
  await elements["community-report-form"].listeners.submit({ preventDefault() {} });
  assert.equal(elements["community-report-form"].hidden, false);
  assert.equal(elements["community-report-submit"].disabled, false);
  assert.match(elements["community-form-status"].textContent, /limit reached/i);
});
