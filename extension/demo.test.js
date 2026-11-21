"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
require("./demo.js");
const demo = globalThis.ChainShieldDemo;

test("demo scenarios are deterministic, labelled and make no provider-backed claims", () => {
  for (const id of Object.keys(demo.scenarios)) {
    const first = demo.createScenario(id);
    const second = demo.createScenario(id);
    assert.deepEqual(first, second);
    assert.equal(first.demo, true);
    assert.match(first.summary, /No provider was contacted/);
    assert.equal(first.evidence.length, 0);
  }
  assert.equal(demo.createScenario("missing"), null);
});
