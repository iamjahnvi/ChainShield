"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
require("./domain-impersonation-view.js");

class MockElement {
  constructor(tagName) { this.tagName = tagName; this.children = []; this.textContent = ""; this.hidden = true; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
}
function mockDocument() {
  const elements = new Map(["results-impersonation", "impersonation-content", "impersonation-status"].map((id) => [id, new MockElement("section")]));
  return { elements, getElementById: (id) => elements.get(id), createElement: (tagName) => new MockElement(tagName) };
}

test("renders API lookalike payload and its official reference instead of unavailable", () => {
  const doc = mockDocument();
  globalThis.ChainShieldDomainImpersonationView.render({ domainImpersonation: {
    status: "possible_lookalike",
    candidateDomain: "metamaskk.io",
    explanation: "Similarity is an indicator, not proof.",
    matches: [{ officialName: "MetaMask", officialDomain: "metamask.io", reason: "One character edit.", confidence: "medium", source: "https://support.metamask.io/" }]
  } }, doc);
  assert.equal(doc.elements.get("results-impersonation").hidden, false);
  assert.match(doc.elements.get("impersonation-status").textContent, /Possible lookalike/);
  assert.doesNotMatch(doc.elements.get("impersonation-status").textContent, /unavailable/);
  const row = doc.elements.get("impersonation-content").children[0];
  assert.match(row.children[0].textContent, /MetaMask · metamask\.io/);
  assert.equal(row.children.at(-1).href, "https://support.metamask.io/");
});

test("renders verified official-domain status, role, review date, and provenance links", () => {
  const doc = mockDocument();
  globalThis.ChainShieldDomainImpersonationView.render({ domainImpersonation: {
    status: "official_domain",
    candidateDomain: "metamask.com",
    explanation: "Listed by first-party sources; no guarantee of page safety.",
    matches: [{ officialName: "MetaMask", officialDomain: "metamask.com", domainRole: "primary", verificationStatus: "first_party_verified", verifiedAt: "2026-11-20", provenance: "MetaMask first-party privacy notice.", reason: "First-party verified domain.", sources: [{ url: "https://metamask.com/privacy-notice" }] }]
  } }, doc);
  assert.match(doc.elements.get("impersonation-status").textContent, /Official domain match/);
  const row = doc.elements.get("impersonation-content").children[0];
  assert.ok(row.children.some((child) => /primary/.test(child.textContent)));
  assert.ok(row.children.some((child) => /2026-11-20/.test(child.textContent)));
  assert.ok(row.children.some((child) => /MetaMask first-party privacy notice/.test(child.textContent)));
  assert.equal(row.children.at(-1).href, "https://metamask.com/privacy-notice");
});

test("renders an unavailable fallback only when the API property is absent", () => {
  const doc = mockDocument();
  globalThis.ChainShieldDomainImpersonationView.render({}, doc);
  assert.equal(doc.elements.get("impersonation-status").textContent, "This check was unavailable in the investigation response.");
});
