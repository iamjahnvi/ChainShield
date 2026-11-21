"use strict";

const { CommunityError } = require("./community");

let fetchImpl = (...args) => fetch(...args);

class CommunityStoreError extends CommunityError {}

function configuration(env = process.env) {
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SECRET_KEY;
  if (typeof url !== "string" || !/^https:\/\//i.test(url) || typeof key !== "string" || !key.trim()) {
    throw new CommunityStoreError("config_missing", "Community reports are not configured.", 503);
  }
  return { url: url.replace(/\/+$/, ""), key };
}

async function rpc(functionName, body, { env = process.env, fetchOverride } = {}) {
  const { url, key } = configuration(env);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 7000);
  try {
    const headers = {
      apikey: key,
      "Content-Type": "application/json",
      Accept: "application/json"
    };
    // Supabase's new sb_secret keys are API keys, not JWTs. Legacy service_role
    // keys are JWTs and must also be supplied as the PostgREST role bearer.
    if (!key.startsWith("sb_secret_")) headers.Authorization = `Bearer ${key}`;

    const response = await (fetchOverride || fetchImpl)(`${url}/rest/v1/rpc/${functionName}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "error"
    });
    let payload;
    try { payload = await response.json(); } catch { payload = null; }
    if (payload?.error === "rate_limited") throw new CommunityStoreError("rate_limited", "Report limit reached. Try again later.", 429);
    if (payload?.error === "duplicate_report") throw new CommunityStoreError("duplicate_report", "A matching report is already in our moderation queue or has been reviewed.", 409);
    if (!response.ok) {
      const message = typeof payload?.message === "string" ? payload.message : "";
      if (message === "rate_limited") throw new CommunityStoreError("rate_limited", "Report limit reached. Try again later.", 429);
      if (message === "duplicate_report") throw new CommunityStoreError("duplicate_report", "A matching report is already in our moderation queue or has been reviewed.", 409);
      if (message === "report_not_found") throw new CommunityStoreError("report_not_found", "Report was not found.", 404);
      throw new CommunityStoreError("database_error", "Community reports are temporarily unavailable.", 503);
    }
    return payload;
  } catch (error) {
    if (error instanceof CommunityError) throw error;
    throw new CommunityStoreError("database_error", "Community reports are temporarily unavailable.", 503);
  } finally {
    clearTimeout(timer);
  }
}

function submitReport(report, hashes, options) {
  return rpc("community_submit_report", {
    p_domain: report.domain,
    p_category: report.category,
    p_description: report.description,
    p_evidence_url: report.evidenceUrl,
    p_reporter_hash: hashes.reporterHash,
    p_duplicate_hash: hashes.duplicateHash
  }, options);
}

function getPublicSummary(domain, options) {
  return rpc("community_public_summary", { p_domain: domain }, options);
}

function getModerationQueue(options) {
  return rpc("community_moderation_queue", { p_limit: 100 }, options);
}

function moderateReport(id, action, options) {
  return rpc("community_moderate_report", { p_report_id: id, p_action: action }, options);
}

function setCommunityFetch(fetcher) {
  fetchImpl = typeof fetcher === "function" ? fetcher : (...args) => fetch(...args);
}

module.exports = { CommunityStoreError, configuration, rpc, submitReport, getPublicSummary, getModerationQueue, moderateReport, setCommunityFetch };
