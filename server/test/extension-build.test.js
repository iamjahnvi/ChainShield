const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { afterEach, test } = require("node:test");
const { buildExtension, validateApiBaseUrl } = require("../../scripts/build-extension");

let outputDirectory;

afterEach(() => {
  if (outputDirectory && fs.existsSync(outputDirectory)) fs.rmSync(outputDirectory, { recursive: true, force: true });
  outputDirectory = undefined;
});

test("production extension build configures the exact HTTPS host and removes localhost permission", () => {
  outputDirectory = path.join(__dirname, "..", "..", `.extension-build-test-${process.pid}`);
  fs.rmSync(outputDirectory, { recursive: true, force: true });
  const output = buildExtension("https://api.example.org/api/", outputDirectory);
  const manifest = JSON.parse(fs.readFileSync(path.join(output, "manifest.json"), "utf8"));
  const config = fs.readFileSync(path.join(output, "config.js"), "utf8");
  assert.deepEqual(manifest.host_permissions, ["https://api.example.org/*"]);
  assert.match(config, /https:\/\/api\.example\.org\/api/);
  assert.ok(!config.includes("localhost"));
  assert.ok(!fs.existsSync(path.join(output, "community.test.js")));
  assert.ok(manifest.permissions.includes("activeTab"));
});

test("production extension builder rejects HTTP and malformed API origins", () => {
  assert.throws(() => validateApiBaseUrl("http://api.example.org/api"), /HTTPS/);
  assert.throws(() => validateApiBaseUrl("not a url"), /valid HTTPS/);
  assert.throws(() => validateApiBaseUrl("https://user:pass@api.example.org/api"), /credentials/);
});
