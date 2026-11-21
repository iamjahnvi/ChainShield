const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { test } = require("node:test");

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.hidden = true; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; }
  set textContent(value) { this._text = value; this.children = []; }
  get textContent() { return this._text || this.children.map((item) => item.textContent || "").join(""); }
}

function renderer() {
  const ids = ["results-alternatives", "results-alternatives-status", "results-alternatives-list"];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element("div")]));
  const document = { getElementById: (id) => elements[id], createElement: (tag) => new Element(tag) };
  const window = {};
  vm.runInNewContext(fs.readFileSync(require.resolve("./safe-alternatives.js"), "utf8"), { document, window, URL });
  return { render: window.renderSafeAlternatives, elements };
}

function descendants(element) {
  return [element, ...element.children.flatMap(descendants)];
}

test("renders verified alternative with a safe official link", () => {
  const { render, elements } = renderer();
  render({ category: "crypto_wallet", recommendations: [{ name: "Wallet", officialDomain: "wallet.example", officialUrl: "https://wallet.example/", verificationStatus: "verified", listingStatus: "listed", description: "Wallet description", reason: "Directory listing", listingSource: "https://directory.example/wallet", verificationSource: "https://registry.example/wallet", verifiedAt: "2026-11-20" }] });
  const card = elements["results-alternatives-list"].children[0].children[1];
  assert.equal(elements["results-alternatives"].hidden, false);
  assert.ok(descendants(card).some((child) => child.tagName === "a" && child.href === "https://wallet.example/"));
  assert.match(card.textContent, /Official domain: verified/);
  assert.ok(descendants(card).some((child) => child.href === "https://directory.example/wallet"));
  assert.ok(descendants(card).some((child) => child.href === "https://registry.example/wallet"));
});

test("renders unverified alternative without making it clickable", () => {
  const { render, elements } = renderer();
  render({ category: "crypto_wallet", recommendations: [{ name: "Candidate", officialUrl: "https://candidate.example", verificationStatus: "unverified" }] });
  const card = elements["results-alternatives-list"].children[0].children[1];
  assert.match(card.textContent, /Official domain: unverified/);
  assert.equal(descendants(card).some((child) => child.href === "https://candidate.example/"), false);
});

test("renders the empty state", () => {
  const { render, elements } = renderer();
  render({ status: "unavailable", recommendations: [] });
  assert.match(elements["results-alternatives-status"].textContent, /No suitable alternatives/);
  assert.equal(elements["results-alternatives-list"].children.length, 1);
});
