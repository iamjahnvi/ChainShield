const assert = require("node:assert/strict");
const { test } = require("node:test");
const { CommunityStoreError, setCommunityFetch, submitReport, getPublicSummary } = require("../src/community-store");

const env = { SUPABASE_URL: "https://db.example.supabase.co", SUPABASE_SECRET_KEY: "sb_secret_test-key" };

function response(payload, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => payload };
}

test("calls the server-side database RPC and forwards only normalized report and pseudonymous hashes", async () => {
  let call;
  setCommunityFetch(async (url, init) => {
    call = { url, init };
    return response({ id: "report-1", status: "pending", submittedAt: "2026-11-20T00:00:00Z" });
  });
  const result = await submitReport({ domain: "example.com", category: "phishing", description: "Description long enough", evidenceUrl: null }, {
    reporterHash: "f".repeat(64), duplicateHash: "a".repeat(64)
  }, { env });
  assert.equal(result.status, "pending");
  assert.match(call.url, /rpc\/community_submit_report$/);
  assert.equal(call.init.headers.apikey, env.SUPABASE_SECRET_KEY);
  assert.equal(call.init.headers.Authorization, undefined);
  assert.ok(call.init.body.includes("f".repeat(64)));
  assert.ok(!call.init.body.includes("203.0.113.4"));
});

test("keeps the Authorization bearer header for legacy service role JWT keys", async () => {
  let call;
  setCommunityFetch(async (_url, init) => {
    call = init;
    return response({ domain: "example.com", totalApproved: 0, categoryCounts: {}, recentReports: [] });
  });
  const legacyKey = "eyJlegacy-service-role-token";
  await getPublicSummary("example.com", { env: { ...env, SUPABASE_SECRET_KEY: legacyKey } });
  assert.equal(call.headers.apikey, legacyKey);
  assert.equal(call.headers.Authorization, `Bearer ${legacyKey}`);
  setCommunityFetch(null);
});

test("maps database rate limit, duplicate, and outage responses to safe errors", async () => {
  for (const [message, code, status] of [["rate_limited", "rate_limited", 429], ["duplicate_report", "duplicate_report", 409], ["private SQL detail", "database_error", 503]]) {
    setCommunityFetch(async () => response({ message }, 400));
    await assert.rejects(getPublicSummary("example.com", { env }), (error) =>
      error instanceof CommunityStoreError && error.code === code && error.status === status && !error.message.includes("private SQL detail")
    );
  }
  setCommunityFetch(async () => { throw new Error("connection detail"); });
  await assert.rejects(getPublicSummary("example.com", { env }), (error) => error.code === "database_error");
  setCommunityFetch(async () => response({ error: "rate_limited" }));
  await assert.rejects(getPublicSummary("example.com", { env }), (error) => error.code === "rate_limited" && error.status === 429);
  setCommunityFetch(null);
});

test("fails closed when database configuration is missing", async () => {
  await assert.rejects(getPublicSummary("example.com", { env: {} }), (error) => error.code === "config_missing");
});
