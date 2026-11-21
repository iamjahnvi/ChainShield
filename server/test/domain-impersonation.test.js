"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { analyzeDomainImpersonation, normalizeHostname } = require("../src/domain-impersonation");

test("recognizes MetaMask.com as first-party verified primary domain", () => {
  assert.equal(analyzeDomainImpersonation("https://metamask.com").status, "official_domain");
  const result = analyzeDomainImpersonation("https://metamask.com");
  assert.equal(result.candidateDomain, "metamask.com");
  assert.equal(result.matches[0].domainRole, "primary");
  assert.equal(result.matches[0].verificationStatus, "first_party_verified");
  assert.equal(result.matches[0].verifiedAt, "2026-11-20");
  assert.ok(result.matches[0].sources.some((source) => source.url === "https://metamask.com/privacy-notice"));
  assert.match(result.matches[0].provenance, /Consensys Software Inc\./);
  assert.match(result.explanation, /does not guarantee/i);
});

test("retains MetaMask.io as a verified first-party redirect alias", () => {
  assert.equal(normalizeHostname("HTTPS://WWW.METAMASK.IO:443/path"), "www.metamask.io");
  const result = analyzeDomainImpersonation("https://metamask.io");
  assert.equal(result.status, "official_domain");
  assert.equal(result.matches[0].domainRole, "redirect_alias");
  assert.equal(result.matches[0].redirectTarget, "metamask.com");
  assert.equal(result.matches[0].verificationStatus, "first_party_redirect_verified");
  assert.ok(result.matches[0].sources.some((source) => source.type === "first_party_redirect_observation"));
});

test("recognizes subdomains of both verified MetaMask domains as official subdomains", () => {
  for (const domain of ["support.metamask.com", "support.metamask.io"]) {
    const result = analyzeDomainImpersonation(`https://${domain}`);
    assert.equal(result.status, "official_subdomain");
    assert.equal(result.candidateDomain, domain.endsWith(".com") ? "metamask.com" : "metamask.io");
  }
});

test("flags a one-character edit as a possible lookalike with explainable official candidate", () => {
  for (const domain of ["metamaskk.com", "metamaskk.io"]) {
    const result = analyzeDomainImpersonation(`https://${domain}`);
    assert.equal(result.status, "possible_lookalike");
    assert.equal(result.matches[0].officialDomain, domain.endsWith(".com") ? "metamask.com" : "metamask.io");
    assert.match(result.matches[0].reason, /differs from the official label/);
    assert.match(result.explanation, /not proof/);
  }
});

test("detects Unicode character substitution after URL punycode normalization", () => {
  const result = analyzeDomainImpersonation("https://unіswap.org");
  assert.equal(result.candidateDomain, "xn--unswap-qvf.org");
  assert.equal(result.status, "possible_lookalike");
});

test("does not confuse a legitimate subdomain with a separate registrable domain", () => {
  assert.equal(analyzeDomainImpersonation("https://wallet.metamask.io").status, "official_subdomain");
});

test("leaves unrelated domains unmatched and malformed values inconclusive", () => {
  assert.equal(analyzeDomainImpersonation("https://example.org").status, "no_match");
  assert.equal(analyzeDomainImpersonation("javascript:alert(1)").status, "inconclusive");
});
