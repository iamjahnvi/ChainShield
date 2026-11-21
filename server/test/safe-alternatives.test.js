const assert = require("node:assert/strict");
const { test } = require("node:test");
const { analyzeCategory, identifyCategory, buildSafeAlternatives, resolveSafeAlternatives, CATEGORIES } = require("../src/safe-alternatives");

const verdict = { status: "suspicious_indicators" };
const evidence = (title, snippet = "") => ({ title, snippet, category: "domain_specific", url: "https://investigated.example/about" });

test("identifies supported purposes from domain-specific evidence, never hostnames alone", () => {
  const cases = [
    ["Crypto wallet provider", CATEGORIES.CRYPTO_WALLET],
    ["Cryptocurrency exchange", CATEGORIES.CRYPTO_EXCHANGE],
    ["NFT marketplace", CATEGORIES.NFT_MARKETPLACE],
    ["Airdrop claim portal", CATEGORIES.AIRDROP_PROJECT],
    ["Investment platform with guaranteed returns", CATEGORIES.INVESTMENT_PLATFORM]
  ];
  for (const [title, category] of cases) assert.equal(identifyCategory({ evidence: [evidence(title)] }), category);
  assert.equal(identifyCategory({ evidence: [{ ...evidence("Welcome"), url: "https://wallet-login.example" }] }), CATEGORIES.UNKNOWN);
  assert.equal(identifyCategory({ evidence: [{ ...evidence("Wallet review", "A directory of wallets"), category: "general_information" }] }), CATEGORIES.UNKNOWN);
});

test("weights titles and snippets and returns evidence confidence", () => {
  const analysis = analyzeCategory([evidence("Crypto wallet", "Ethereum wallet account")]);
  assert.equal(analysis.category, CATEGORIES.CRYPTO_WALLET);
  assert.ok(analysis.confidence >= 0.72);
  assert.deepEqual(analysis.evidence, ["https://investigated.example/about"]);
});

test("conflicting category evidence stays unknown", () => {
  assert.equal(identifyCategory({ evidence: [evidence("Crypto wallet"), evidence("NFT marketplace")] }), CATEGORIES.UNKNOWN);
  assert.equal(identifyCategory({ evidence: [evidence("Wallet investment platform")] }), CATEGORIES.UNKNOWN);
});

test("catalogue returns wallet and NFT entries with separate listing and domain verification provenance", () => {
  for (const [title, category, expected] of [
    ["Crypto wallet", CATEGORIES.CRYPTO_WALLET, "MetaMask"],
    ["NFT marketplace", CATEGORIES.NFT_MARKETPLACE, "OpenSea"]
  ]) {
    const result = buildSafeAlternatives({ evidence: [evidence(title)], verdict, now: new Date("2026-11-20T00:00:00Z") });
    assert.equal(result.category, category);
    assert.equal(result.recommendations.length, 1);
    const recommendation = result.recommendations[0];
    assert.equal(recommendation.name, expected);
    assert.equal(recommendation.verificationStatus, "verified");
    assert.equal(recommendation.listingStatus, "listed");
    assert.ok(recommendation.listingSource.startsWith("https://"));
    assert.ok(recommendation.verificationSource.startsWith("https://"));
    assert.match(recommendation.reason, /does not establish that the service is safe/i);
  }
});

test("unsupported categories, stale entries, missing provenance, and non-concerning verdicts return no recommendations", () => {
  for (const title of ["Cryptocurrency exchange", "Airdrop claim portal", "Investment platform"]) {
    assert.equal(buildSafeAlternatives({ evidence: [evidence(title)], verdict, now: new Date("2026-11-20T00:00:00Z") }).recommendations.length, 0);
  }
  assert.equal(buildSafeAlternatives({ evidence: [evidence("Crypto wallet")], verdict: { status: "no_known_threats_found" } }).recommendations.length, 0);
  assert.equal(buildSafeAlternatives({ evidence: [evidence("Crypto wallet")], verdict, now: new Date("2027-06-01T00:00:00Z") }).recommendations.length, 0);
  assert.equal(buildSafeAlternatives({ evidence: [evidence("Crypto wallet")], verdict, now: new Date("2026-01-01T00:00:00Z") }).recommendations.length, 0);
  const noProvenance = { ...buildSafeAlternatives({ evidence: [evidence("Crypto wallet")], verdict, now: new Date("2026-11-20T00:00:00Z") }).recommendations[0], verificationSource: "" };
  assert.deepEqual(buildSafeAlternatives({ evidence: [evidence("Crypto wallet")], verdict, now: new Date("2026-11-20T00:00:00Z"), catalog: { [CATEGORIES.CRYPTO_WALLET]: [noProvenance] } }).recommendations, []);
});

test("alternative provider failures become an empty result without throwing", () => {
  const result = resolveSafeAlternatives({}, () => { throw new Error("provider unavailable"); });
  assert.equal(result.status, "unavailable");
  assert.equal(result.unavailableReason, "provider_error");
  assert.deepEqual(result.recommendations, []);
});

test("missing evidence returns a clear empty state", () => {
  const result = buildSafeAlternatives({ evidence: [], verdict });
  assert.equal(result.category, "unknown");
  assert.deepEqual(result.recommendations, []);
  assert.equal(result.unavailableReason, "purpose_unclear");
});
