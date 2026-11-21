const assert = require("node:assert/strict");
const { after, before, test } = require("node:test");
const app = require("../src/app");
const { setCommunityFetch } = require("../src/community-store");

const envKeys = ["SUPABASE_URL", "SUPABASE_SECRET_KEY", "COMMUNITY_HASH_SECRET", "COMMUNITY_ADMIN_TOKEN"];
const originalEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));
let server;
let baseUrl;
let rpcCalls;
let serialQueue = Promise.resolve();

function serialTest(name, fn) {
  test(name, async () => {
    let release;
    const previous = serialQueue;
    serialQueue = new Promise((resolve) => { release = resolve; });
    await previous;
    try { await fn(); }
    finally { setCommunityFetch(null); release(); }
  });
}

function jsonResponse(payload, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => payload };
}

before(async () => {
  for (const key of envKeys) process.env[key] = key === "SUPABASE_URL" ? "https://chainshield-test.supabase.co" : `${key.toLowerCase()}-test-secret-with-more-than-32-characters`;
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  for (const key of envKeys) {
    if (originalEnv[key] === undefined) delete process.env[key];
    else process.env[key] = originalEnv[key];
  }
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

function mockRpc(callback) {
  rpcCalls = [];
  setCommunityFetch(async (url, init) => {
    const body = JSON.parse(init.body);
    const name = url.split("/").pop();
    rpcCalls.push({ name, body, headers: init.headers });
    return callback(name, body);
  });
}

serialTest("public domain endpoint normalizes host and returns only community context", async () => {
  mockRpc((name, body) => {
    assert.equal(name, "community_public_summary");
    assert.equal(body.p_domain, "example.com");
    return jsonResponse({ domain: "example.com", totalApproved: 2, categoryCounts: { phishing: 2 }, recentReports: [{ category: "phishing", description: "Two separate approved reports describe credential capture.", evidenceUrl: null, submittedAt: "2026-11-19T00:00:00Z" }], pendingReports: 1000 });
  });
  const response = await fetch(`${baseUrl}/api/community/domains/www.example.com`);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.totalApproved, 2);
  assert.equal(body.source, "community_reports");
  assert.equal(body.trust, "unverified_user_submissions");
  assert.equal(body.pendingReports, undefined);
  assert.match(body.disclaimer, /do not determine the security verdict/i);
});

serialTest("valid submissions are pending, invalid submissions stop before storage", async () => {
  mockRpc((name) => {
    assert.equal(name, "community_submit_report");
    return jsonResponse({ id: "123e4567-e89b-12d3-a456-426614174000", status: "pending", submittedAt: "2026-11-20T00:00:00Z" });
  });
  const invalid = await fetch(`${baseUrl}/api/community/reports`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: "example.com", category: "invalid", description: "This is a valid length description." }) });
  assert.equal(invalid.status, 400);
  assert.equal(rpcCalls.length, 0);

  const response = await fetch(`${baseUrl}/api/community/reports`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: "https://login.example.com/path", category: "phishing", description: "This page requests my wallet seed phrase." }) });
  const body = await response.json();
  assert.equal(response.status, 202);
  assert.equal(body.domain, "example.com");
  assert.equal(body.status, "pending");
  assert.match(body.message, /moderation/i);
  assert.equal(rpcCalls[0].body.p_domain, "example.com");
  assert.equal(rpcCalls[0].body.p_reporter_hash.length, 64);
  assert.equal(JSON.stringify(rpcCalls[0].body).includes("127.0.0.1"), false);
});

serialTest("duplicate, rate-limited, and database failures are mapped to explicit responses", async () => {
  for (const [message, expected] of [["duplicate_report", 409], ["rate_limited", 429], ["SQL secret", 503]]) {
    mockRpc(() => jsonResponse({ message }, 400));
    const response = await fetch(`${baseUrl}/api/community/reports`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: "example.com", category: "other", description: "A sufficiently long community report." }) });
    assert.equal(response.status, expected);
    assert.ok(!(await response.text()).includes("SQL secret"));
  }
});

serialTest("moderation queue and actions require the configured admin token", async () => {
  mockRpc((name) => name === "community_moderation_queue" ? jsonResponse([{ id: "123e4567-e89b-12d3-a456-426614174000", status: "pending" }]) : jsonResponse({ id: "123e4567-e89b-12d3-a456-426614174000", status: "approved" }));
  const unauth = await fetch(`${baseUrl}/api/community/admin/reports`);
  assert.equal(unauth.status, 401);
  const authorized = await fetch(`${baseUrl}/api/community/admin/reports`, { headers: { Authorization: `Bearer ${process.env.COMMUNITY_ADMIN_TOKEN}` } });
  assert.equal(authorized.status, 200);
  assert.equal((await authorized.json()).reports[0].status, "pending");
  const action = await fetch(`${baseUrl}/api/community/admin/reports/123e4567-e89b-12d3-a456-426614174000/moderation`, { method: "POST", headers: { Authorization: `Bearer ${process.env.COMMUNITY_ADMIN_TOKEN}`, "Content-Type": "application/json" }, body: JSON.stringify({ action: "approve" }) });
  assert.equal(action.status, 200);
  assert.equal((await action.json()).status, "approved");
  assert.equal(rpcCalls.at(-1).name, "community_moderate_report");
});

serialTest("isolated mock keeps pending submissions private and exercises moderation transitions", async () => {
  const domain = "chainshield-test.example.com";
  const ids = [
    "123e4567-e89b-42d3-a456-426614174000",
    "123e4567-e89b-42d3-a456-426614174001",
    "123e4567-e89b-42d3-a456-426614174002"
  ];
  const records = [];
  mockRpc((name, body) => {
    if (name === "community_submit_report") {
      const record = { id: ids[records.length], domain: body.p_domain, category: body.p_category, description: body.p_description, status: "pending", submittedAt: "2026-11-20T00:00:00.000Z" };
      records.push(record);
      return jsonResponse({ id: record.id, status: record.status, submittedAt: record.submittedAt });
    }
    if (name === "community_moderation_queue") return jsonResponse(records.filter((record) => record.status === "pending"));
    if (name === "community_public_summary") {
      const approved = records.filter((record) => record.domain === body.p_domain && record.status === "approved");
      return jsonResponse({ domain: body.p_domain, totalApproved: approved.length, categoryCounts: approved.reduce((counts, record) => ({ ...counts, [record.category]: (counts[record.category] || 0) + 1 }), {}), recentReports: approved.map(({ category, description, submittedAt }) => ({ category, description, submittedAt, evidenceUrl: null })) });
    }
    if (name === "community_moderate_report") {
      const record = records.find((item) => item.id === body.p_report_id);
      if (body.p_action === "remove") { record.status = "removed"; return jsonResponse({ id: record.id, status: "removed" }); }
      record.status = body.p_action === "approve" ? "approved" : "rejected";
      return jsonResponse({ id: record.id, status: record.status });
    }
    throw new Error(`Unexpected mock RPC: ${name}`);
  });

  for (const [category, description] of [
    ["phishing", "Test record one for approval workflow."],
    ["other", "Test record two for rejection workflow."],
    ["other", "Test record three for removal workflow."]
  ]) {
    const response = await fetch(`${baseUrl}/api/community/reports`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain, category, description }) });
    assert.equal(response.status, 202);
    assert.equal((await response.json()).status, "pending");
  }

  const queue = await fetch(`${baseUrl}/api/community/admin/reports`, { headers: { Authorization: `Bearer ${process.env.COMMUNITY_ADMIN_TOKEN}` } });
  assert.equal(queue.status, 200);
  assert.equal((await queue.json()).reports.length, 3);

  const beforeApproval = await fetch(`${baseUrl}/api/community/domains/${domain}`);
  const hidden = await beforeApproval.json();
  assert.equal(hidden.totalApproved, 0);
  assert.deepEqual(hidden.recentReports, []);

  for (const [id, action, expected] of [[ids[0], "approve", "approved"], [ids[1], "reject", "rejected"], [ids[2], "remove", "removed"]]) {
    const response = await fetch(`${baseUrl}/api/community/admin/reports/${id}/moderation`, { method: "POST", headers: { Authorization: `Bearer ${process.env.COMMUNITY_ADMIN_TOKEN}`, "Content-Type": "application/json" }, body: JSON.stringify({ action }) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, expected);
  }

  const afterApproval = await fetch(`${baseUrl}/api/community/domains/${domain}`);
  const visible = await afterApproval.json();
  assert.equal(visible.totalApproved, 1);
  assert.equal(visible.recentReports[0].category, "phishing");
  assert.equal(rpcCalls.length, 9);
});

serialTest("database outages are isolated to community endpoints", async () => {
  mockRpc(() => { throw new Error("connection secret"); });
  const response = await fetch(`${baseUrl}/api/community/domains/example.com`);
  assert.equal(response.status, 503);
  assert.doesNotMatch(await response.text(), /connection secret/);
});
