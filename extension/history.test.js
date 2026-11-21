"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
require("./history.js");
const history = globalThis.ChainShieldHistory;

function memoryStorage(initial = "[]") {
  const values = new Map([[history.KEY, initial]]);
  return { getItem: (key) => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
}
function record(id) { return { id, url: `https://${id}.example/`, timestamp: new Date().toISOString(), data: { verdict: { status: id } } }; }

test("history bounds storage, ignores malformed entries and handles corrupted JSON", () => {
  const storage = memoryStorage("not-json");
  assert.deepEqual(history.read(storage), []);
  let result = [];
  for (let i = 0; i < history.LIMIT + 3; i += 1) result = history.save(record(String(i)), storage);
  assert.equal(result.length, history.LIMIT);
  assert.equal(result[0].id, String(history.LIMIT + 2));
  storage.setItem(history.KEY, JSON.stringify([record("ok"), { id: "bad" }]));
  assert.deepEqual(history.read(storage).map((item) => item.id), ["ok"]);
});

test("history comparison highlights verdict, providers, heuristic and impersonation changes", () => {
  const before = { data: { verdict: { status: "inconclusive" }, providers: [{ id: "sb", status: "unavailable" }], evidence: [{ title: "Old source", url: "https://source.example/old" }], urlSignals: { findings: [] }, domainImpersonation: { status: "no_match" } } };
  const after = { data: { verdict: { status: "suspicious_indicators" }, providers: [{ id: "sb", status: "reported" }], evidence: [{ title: "New source", url: "https://source.example/new" }], urlSignals: { findings: [{ ruleId: "punycode" }] }, domainImpersonation: { status: "possible_lookalike" } } };
  assert.equal(history.compare(before, after).length, 5);
});
