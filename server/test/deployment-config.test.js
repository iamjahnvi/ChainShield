const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

test("Vercel deploys the backend package as a bounded Node.js Express app", () => {
  const serverRoot = path.join(__dirname, "..");
  const config = JSON.parse(fs.readFileSync(path.join(serverRoot, "vercel.json"), "utf8"));
  const packageJson = JSON.parse(fs.readFileSync(path.join(serverRoot, "package.json"), "utf8"));
  assert.equal(require(path.join(serverRoot, "index.js")), require("../src/app"));
  assert.ok(packageJson.dependencies.express);
  assert.equal(config.functions["index.js"].maxDuration, 60);
  assert.ok(!fs.existsSync(path.join(serverRoot, "../vercel.json")));
});
