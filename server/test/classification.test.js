const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  CATEGORIES,
  canonicalizeUrl,
  classifyEntry,
  normalizeHost,
  prepareEvidence
} = require("../src/classification");
const { buildInvestigationQuery } = require("../src/tinyfish");

test("investigation query targets the exact hostname with focused threat terms", () => {
  const query = buildInvestigationQuery("shop.example.com");

  assert.ok(query.includes("shop.example.com"));
  assert.ok(query.includes("scam"));
  assert.ok(query.includes("phishing"));
  assert.ok(query.includes("impersonation"));
  assert.ok(query.includes("fraud"));
  assert.ok(query.includes("security report"));
});

test("canonicalizeUrl normalizes casing and removes tracking params", () => {
  assert.equal(
    canonicalizeUrl("HTTPS://Example.COM/Path/?utm_source=news&b=2&a=1#frag"),
    "https://example.com/Path/?b=2&a=1#frag"
  );
  assert.equal(
    canonicalizeUrl("https://example.com/"),
    "https://example.com/"
  );
  assert.equal(
    canonicalizeUrl("https://example.com/page?fbclid=abc&gclid=xyz"),
    "https://example.com/page"
  );
});

test("canonicalizeUrl preserves scheme and fragments and rejects non-http URLs", () => {
  assert.ok(
    canonicalizeUrl("http://example.com/page").startsWith("http://example.com")
  );
  assert.notEqual(
    canonicalizeUrl("http://example.com/page"),
    canonicalizeUrl("https://example.com/page")
  );
  assert.equal(
    canonicalizeUrl("https://example.com/page#section"),
    "https://example.com/page#section"
  );
  assert.notEqual(
    canonicalizeUrl("https://example.com/page#one"),
    canonicalizeUrl("https://example.com/page#two")
  );
  assert.notEqual(
    canonicalizeUrl("https://example.com/page?"),
    canonicalizeUrl("https://example.com/page")
  );
  assert.equal(canonicalizeUrl("javascript:alert(1)"), "");
  assert.equal(canonicalizeUrl("not a url"), "");
});

test("prepareEvidence deduplicates matching URLs after tracking cleanup", () => {
  const entries = [
    { title: "Bare", url: "https://shop.example.com/page" },
    { title: "Tracked", url: "https://shop.example.com/page?utm_campaign=x" },
    { title: "Cased", url: "HTTPS://SHOP.EXAMPLE.COM/page/" },
    { title: "Params a", url: "https://shop.example.com/page?b=2&a=1" },
    { title: "Params b", url: "https://shop.example.com/page?a=1&b=2" },
    { title: "Fragment", url: "https://shop.example.com/page#top" },
    { title: "Scheme", url: "http://shop.example.com/page" },
    { title: "Repeated params", url: "https://shop.example.com/page?a=1&a=2" },
    { title: "Reordered repeated params", url: "https://shop.example.com/page?a=2&a=1" },
    { title: "No url", snippet: "first" },
    { title: "No url", snippet: "second" }
  ];

  const prepared = prepareEvidence(entries, "shop.example.com");

  assert.deepEqual(
    prepared.map((entry) => entry.title),
    [
      "Bare",
      "Cased",
      "Params a",
      "Params b",
      "Fragment",
      "Scheme",
      "Repeated params",
      "Reordered repeated params",
      "No url",
      "No url"
    ]
  );
});

test("deduplication preserves trailing slashes and query parameter order", () => {
  const entries = [
    { title: "No slash", url: "https://shop.example.com/page?a=1&b=2" },
    { title: "Trailing slash", url: "https://shop.example.com/page/?a=1&b=2" },
    { title: "Reordered parameters", url: "https://shop.example.com/page?b=2&a=1" }
  ];

  assert.deepEqual(
    prepareEvidence(entries, "shop.example.com").map((entry) => entry.title),
    ["No slash", "Trailing slash", "Reordered parameters"]
  );
});

test("URL host on the investigated hostname is domain-specific but not proof", () => {
  const result = classifyEntry(
    { title: "Welcome", url: "https://shop.example.com/about" },
    "shop.example.com"
  );

  assert.equal(result.category, CATEGORIES.DOMAIN_SPECIFIC);
  assert.match(result.categoryReason, /on the investigated hostname/i);
  assert.match(result.categoryReason, /does not establish maliciousness/i);
});

test("subdomains of the investigated hostname are domain-specific", () => {
  const result = classifyEntry(
    { title: "Portal", url: "https://login.shop.example.com/x" },
    "shop.example.com"
  );

  assert.equal(result.category, CATEGORIES.DOMAIN_SPECIFIC);
  assert.match(result.categoryReason, /subdomain of the investigated hostname/i);
});

test("parent and sibling domains are not subdomains of the investigated hostname", () => {
  const parent = classifyEntry(
    { title: "Example Inc", url: "https://example.com/home" },
    "shop.example.com"
  );
  assert.notEqual(parent.category, CATEGORIES.DOMAIN_SPECIFIC);
  assert.equal(
    parent.categoryReason,
    "Refers to the parent domain rather than the investigated hostname."
  );

  const sibling = classifyEntry(
    { title: "Sibling", url: "https://sibling.example.com/x" },
    "shop.example.com"
  );
  assert.notEqual(sibling.category, CATEGORIES.DOMAIN_SPECIFIC);
  assert.equal(
    sibling.categoryReason,
    "No clear connection to the investigated hostname."
  );
});

test("hostname matches respect character boundaries", () => {
  const embeddedHost = classifyEntry(
    { title: "See notwww.example.com for details", url: "https://other.example.net/a" },
    "www.example.com"
  );
  assert.notEqual(embeddedHost.category, CATEGORIES.DOMAIN_SPECIFIC);

  const embeddedText = classifyEntry(
    { title: "Mention of notwww.example.com today", url: "https://other.example.net/b" },
    "www.example.com"
  );
  assert.equal(embeddedText.category, CATEGORIES.IRRELEVANT_OR_UNCLEAR);
  assert.equal(embeddedText.categoryReason, "No clear connection to the investigated hostname.");
});

test("a domain-focused report in the text is domain-specific", () => {
  const result = classifyEntry(
    { title: "Shop.example.com review: is it a scam or legitimate store?", url: "https://reviews.example.net/shop" },
    "shop.example.com"
  );

  assert.equal(result.category, CATEGORIES.DOMAIN_SPECIFIC);
  assert.match(result.categoryReason, /about the investigated hostname itself/i);
  assert.match(result.categoryReason, /does not establish maliciousness/i);
});

test("a passing hostname mention with a security term is only general information", () => {
  const result = classifyEntry(
    { title: "Weekly fraud report: shop.example.com among 20 sites listed", url: "https://news.example.org/roundup" },
    "shop.example.com"
  );

  assert.equal(result.category, CATEGORIES.GENERAL_INFORMATION);
  assert.match(result.categoryReason, /passing mention/i);
});

test("a passing hostname mention without a security term is unclear", () => {
  const result = classifyEntry(
    { title: "Nice pages at shop.example.com today", url: "https://blog.example.org/post" },
    "shop.example.com"
  );

  assert.equal(result.category, CATEGORIES.IRRELEVANT_OR_UNCLEAR);
  assert.match(result.categoryReason, /passing mention/i);
});

test("security terms without any hostname reference are general information", () => {
  const result = classifyEntry(
    { title: "How to spot phishing emails", url: "https://guides.example.org/phishing" },
    "shop.example.com"
  );

  assert.equal(result.category, CATEGORIES.GENERAL_INFORMATION);
  assert.match(result.categoryReason, /does not mention the investigated hostname/i);
});

test("unrelated results are irrelevant or unclear", () => {
  const result = classifyEntry(
    { title: "Cat food reviews", url: "https://pets.example.org/cats" },
    "shop.example.com"
  );

  assert.equal(result.category, CATEGORIES.IRRELEVANT_OR_UNCLEAR);
  assert.equal(result.categoryReason, "No clear connection to the investigated hostname.");
});

test("investigated hostname is normalized before matching", () => {
  assert.equal(normalizeHost(" Shop.Example.COM. "), "shop.example.com");

  const result = classifyEntry(
    { title: "Portal", url: "https://login.shop.example.com/" },
    "Shop.Example.COM."
  );
  assert.equal(result.category, CATEGORIES.DOMAIN_SPECIFIC);
});

test("prepareEvidence keeps result order while attaching categories", () => {
  const entries = [
    { title: "On host", url: "https://shop.example.com/a" },
    { title: "How to spot phishing emails", url: "https://guides.example.org/phishing" },
    { title: "Unrelated", url: "https://pets.example.org/cats" },
    { title: "Duplicate", url: "https://shop.example.com/a?utm_source=y" }
  ];

  const prepared = prepareEvidence(entries, "shop.example.com");

  assert.deepEqual(
    prepared.map((entry) => entry.category),
    [
      CATEGORIES.DOMAIN_SPECIFIC,
      CATEGORIES.GENERAL_INFORMATION,
      CATEGORIES.IRRELEVANT_OR_UNCLEAR
    ]
  );
  for (const entry of prepared) {
    assert.equal(typeof entry.categoryReason, "string");
    assert.ok(entry.categoryReason.length > 0);
  }
});
