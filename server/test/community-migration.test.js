const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

test("migration defaults reports to pending, gates public queries, and reserves moderation for backend role", () => {
  const migration = fs.readFileSync(path.join(__dirname, "../migrations/001_community_reports.sql"), "utf8");
  assert.match(migration, /status text not null default 'pending'/i);
  assert.match(migration, /where domain = p_domain and status = 'approved'/i);
  assert.match(migration, /'totalApproved', \(\s*select count\(\*\)/i);
  assert.match(migration, /where status = 'pending'/i);
  assert.match(migration, /enable row level security/i);
  assert.match(migration, /revoke all on public\.community_reports, public\.community_rate_limits from anon, authenticated/i);
  assert.match(migration, /p_action not in \('approve', 'reject', 'remove'\)/i);
  assert.match(migration, /where id = p_report_id and status = 'pending'/i);
  assert.match(migration, /grant execute on function public\.community_moderate_report\(uuid, text\) to service_role/i);
});
