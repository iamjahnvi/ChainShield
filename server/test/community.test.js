const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  CommunityError, normalizeDomain, normalizeDescription, normalizeEvidenceUrl,
  validateReport, hashForDuplicate, hashReporter
} = require("../src/community");

test("normalizes URLs and subdomains to a common registrable domain", () => {
  assert.equal(normalizeDomain("https://www.login.example.com/path?q=x"), "example.com");
  assert.equal(normalizeDomain("login.example.co.uk"), "example.co.uk");
  assert.equal(normalizeDomain("WWW.Example.COM."), "example.com");
  assert.equal(normalizeDomain("foo.vercel.app"), "foo.vercel.app");
  assert.equal(normalizeDomain("bar.github.io"), "bar.github.io");
});

test("rejects local, IP, public-suffix, malformed, and credential-bearing domains", () => {
  for (const value of ["localhost", "http://127.0.0.1", "co.uk", "https://user:pass@example.com", "javascript:alert(1)", "bad domain"]) {
    assert.throws(() => normalizeDomain(value), (error) => error instanceof CommunityError && error.status === 400);
  }
});

test("validates categories, trims controls, and limits report fields", () => {
  const report = validateReport({ domain: "www.example.com", category: "phishing", description: "  This page asks for my password.\n  ", evidenceUrl: "https://reports.example.net/case/1" });
  assert.deepEqual(report, { domain: "example.com", category: "phishing", description: "This page asks for my password.", evidenceUrl: "https://reports.example.net/case/1" });
  assert.throws(() => validateReport({ domain: "example.com", category: "bogus", description: "This description is long enough." }), /category/i);
  assert.throws(() => normalizeDescription("short"), /12 to 500/i);
  assert.throws(() => normalizeDescription("x".repeat(501)), /12 to 500/i);
  assert.match(normalizeDescription("Report from alice@example.com was about phishing."), /\[email redacted\]/);
  assert.match(normalizeDescription("Wallet 0x0123456789012345678901234567890123456789 was prompted."), /\[wallet data redacted\]/);
});

test("evidence links must be public HTTPS URLs without credentials", () => {
  assert.equal(normalizeEvidenceUrl(""), null);
  assert.equal(normalizeEvidenceUrl("https://example.com/report?token=secret#fragment"), "https://example.com/report");
  for (const value of ["http://example.com/report", "javascript:alert(1)", "https://user:pass@example.com", "https://localhost/report", "https://127.0.0.1/report"]) {
    assert.throws(() => normalizeEvidenceUrl(value), /HTTPS|public domain/i);
  }
});

test("duplicate hashes are normalized and reporter identifier is keyed without storing the input", () => {
  const one = { domain: "example.com", category: "phishing", description: "Repeated report text" };
  const two = { ...one, description: " repeated REPORT TEXT " };
  assert.equal(hashForDuplicate(one), hashForDuplicate(two));
  const hash = hashReporter("203.0.113.4", "a-secret-with-more-than-32-bytes-to-hash-ip");
  assert.match(hash, /^[a-f0-9]{64}$/);
  assert.ok(!hash.includes("203.0.113.4"));
  assert.throws(() => hashReporter("ip", "too-short"), /not configured/i);
});
