"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
require("./action-center.js");
const analyze = globalThis.ChainShieldActionCenter.analyze;

function result(status, extra = {}) {
  return { verdict: { status }, threatAssessment: { status: "no_match", providers: [] }, domainImpersonation: { status: "no_match", matches: [] }, urlSignals: { findings: [] }, providers: [{ id: "tinyfish_search", status: "available" }], evidence: [], ...extra };
}

test("confirmed threat and suspicious verdicts produce proportionate next steps", () => {
  const threat = analyze(result("known_threat_detected", { threatAssessment: { status: "reported", providers: [] } }));
  assert.match(threat.recommendation, /Avoid interacting/);
  assert.match(threat.importantSignal, /threat match/);
  const suspicious = analyze(result("suspicious_indicators", { urlSignals: { findings: [{ explanation: "Deep hostname structure." }] } }));
  assert.match(suspicious.recommendation, /independently verify/);
  assert.equal(suspicious.importantSignal, "Deep hostname structure.");
});

test("possible lookalike recommendation is based on the domain analysis field", () => {
  const model = analyze(result("no_known_threats_found", { domainImpersonation: { status: "possible_lookalike", matches: [{ officialDomain: "metamask.com" }] } }));
  assert.equal(model.verdictLabel, "No known threats found");
  assert.match(model.explanation, /resembles a verified official website/);
  assert.match(model.recommendation, /Do not connect your wallet/);
  assert.equal(model.checklist[0].state, "Signal found");
});

test("exact official domain and official subdomain are distinguished", () => {
  const exact = analyze(result("no_known_threats_found", { domainImpersonation: { status: "official_domain", matches: [] } }));
  const subdomain = analyze(result("no_known_threats_found", { domainImpersonation: { status: "official_subdomain", matches: [] } }));
  assert.match(exact.explanation, /domain matches/);
  assert.match(subdomain.explanation, /subdomain is within/);
  assert.equal(exact.checklist[0].state, "Verified");
  assert.equal(subdomain.checklist[0].state, "Verified");
  const officialVerdict = analyze(result("trusted_official_domain", { domainImpersonation: { status: "official_domain", matches: [] } }));
  assert.equal(officialVerdict.verdictLabel, "Verified official domain");
});

test("no-known-threats and inconclusive use honest explanations and actions", () => {
  const clean = analyze(result("no_known_threats_found"));
  assert.match(clean.explanation, /does not establish.*safe/);
  assert.match(clean.recommendation, /normal caution/);
  const uncertain = analyze(result("inconclusive"));
  assert.match(uncertain.explanation, /Not enough reliable evidence/);
  assert.match(uncertain.recommendation, /Avoid sensitive interactions/);
});

test("unavailable providers are surfaced instead of treated as successful checks", () => {
  const model = analyze(result("inconclusive", { threatAssessment: { status: "unavailable", providers: [{ id: "google_safe_browsing", status: "unavailable" }] }, providers: [{ id: "tinyfish_search", status: "unavailable" }] }));
  assert.ok(model.checklist.some((entry) => entry.label === "Threat reputation" && entry.state === "Unavailable"));
  assert.ok(model.checklist.some((entry) => entry.label === "Important providers" && entry.state === "Unavailable"));
  assert.ok(model.attention.some((entry) => /provider check.*unavailable/.test(entry)));
});

test("contract checklist is omitted unless relevant and distinguishes completed analysis", () => {
  const noContract = analyze(result("no_known_threats_found"));
  assert.equal(noContract.checklist.some((entry) => entry.label === "Contract analysis"), false);
  const completed = analyze(result("no_known_threats_found", { ethereumAssessment: { status: "available" }, contractAnalysis: { status: "incomplete" } }));
  assert.equal(completed.checklist.find((entry) => entry.label === "Contract analysis").state, "Verified");
  assert.match(completed.checklist.find((entry) => entry.label === "Contract analysis").detail, /does not establish whether it is safe/);
  const unavailable = analyze(result("no_known_threats_found", { ethereumAssessment: { status: "unavailable" } }));
  assert.equal(unavailable.checklist.find((entry) => entry.label === "Contract analysis").state, "Unavailable");
});

test("community reports add context without changing recommendation", () => {
  const data = result("no_known_threats_found");
  const before = analyze(data);
  const after = analyze(data, { totalApproved: 7 });
  assert.equal(after.recommendation, before.recommendation);
  assert.ok(after.attention.some((entry) => /7 approved/.test(entry)));
  assert.equal(after.checklist.at(-1).state, "Signal found");
  const unavailable = analyze(data, { status: "unavailable" });
  assert.equal(unavailable.recommendation, before.recommendation);
  assert.ok(unavailable.checklist.some((entry) => entry.label === "Approved community reports" && entry.state === "Unavailable"));
});

test("domain-specific evidence is prioritized over general search context", () => {
  const model = analyze(result("no_known_threats_found", { evidence: [{ category: "general_information" }, { category: "domain_specific" }] }));
  assert.equal(model.evidenceGroup, "domain_specific");
  assert.match(model.importantSignal, /directly associated/);
  const contextOnly = analyze(result("no_known_threats_found", { evidence: [{ category: "general_information" }] }));
  assert.equal(contextOnly.evidenceGroup, "general_context");
  assert.match(contextOnly.importantSignal, /general or unclear/);
});

test("missing and malformed result fields fail safely without invented scores", () => {
  const model = analyze({ verdict: { status: null }, providers: "bad", evidence: {}, urlSignals: { findings: "bad" }, domainImpersonation: { status: "unknown" } });
  assert.equal(model.verdictLabel, "Inconclusive");
  assert.match(model.recommendation, /Avoid sensitive interactions/);
  assert.equal("riskScore" in model, false);
  assert.equal(model.evidenceGroup, "none");
});

test("renders plain text fields and checklist states into the Action Center", () => {
  class Node {
    constructor(tag) { this.tagName = tag; this.children = []; this.hidden = true; this.dataset = {}; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = [...nodes]; }
    set textContent(value) { this._text = String(value); this.children = []; }
    get textContent() { return this._text || this.children.map((child) => child.textContent || "").join(""); }
  }
  const ids = ["action-center", "action-verdict", "action-explanation", "action-recommendation", "action-signal", "action-attention", "action-attention-block", "action-checklist"];
  const elements = Object.fromEntries(ids.map((id) => [id, new Node("section")]));
  const doc = { getElementById: (id) => elements[id], createElement: (tag) => new Node(tag) };
  globalThis.ChainShieldActionCenter.render(result("inconclusive"), doc);
  assert.equal(elements["action-center"].hidden, false);
  assert.equal(elements["action-verdict"].textContent, "Inconclusive");
  assert.match(elements["action-recommendation"].textContent, /Avoid sensitive interactions/);
  assert.ok(elements["action-checklist"].children.length >= 3);
});
