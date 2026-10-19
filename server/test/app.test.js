const assert = require("node:assert/strict");
const { after, before, test } = require("node:test");
const app = require("../src/app");

let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
});

test("health endpoint reports that the backend is running", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok" });
});

test("investigation endpoint rejects missing and malformed URLs", async (t) => {
  const cases = [
    { name: "missing URL", body: {}, error: "A URL is required." },
    { name: "malformed URL", body: { url: "not a URL" }, error: "The URL is malformed." },
    { name: "unsupported protocol", body: { url: "file:///etc/passwd" }, error: "Only HTTP and HTTPS URLs are supported." }
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      const response = await fetch(`${baseUrl}/api/investigations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(testCase.body)
      });

      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: testCase.error });
    });
  }
});
