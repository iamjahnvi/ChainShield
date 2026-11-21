"use strict";

const crypto = require("crypto");
const express = require("express");
const {
  CommunityError,
  normalizeDomain,
  validateReport,
  hashForDuplicate,
  hashReporter
} = require("../community");
const store = require("../community-store");

const router = express.Router();

function adminAuthorized(req) {
  const configured = process.env.COMMUNITY_ADMIN_TOKEN;
  const provided = req.get("Authorization")?.replace(/^Bearer\s+/i, "");
  if (typeof configured !== "string" || configured.length < 32 || typeof provided !== "string") return false;
  const expectedDigest = crypto.createHash("sha256").update(configured).digest();
  const providedDigest = crypto.createHash("sha256").update(provided).digest();
  return crypto.timingSafeEqual(expectedDigest, providedDigest);
}

function requireAdmin(req, res, next) {
  if (!process.env.COMMUNITY_ADMIN_TOKEN || process.env.COMMUNITY_ADMIN_TOKEN.length < 32) {
    return res.status(503).json({ error: "Community moderation is not configured." });
  }
  if (!adminAuthorized(req)) return res.status(401).json({ error: "Administrator authorization is required." });
  return next();
}

function reportFailure(res, error) {
  if (error instanceof CommunityError) return res.status(error.status).json({ error: error.message, code: error.code });
  return res.status(503).json({ error: "Community reports are temporarily unavailable.", code: "provider_error" });
}

router.get("/domains/:domain", async (req, res) => {
  let domain;
  try { domain = normalizeDomain(req.params.domain); }
  catch (error) { return reportFailure(res, error); }
  try {
    const summary = await store.getPublicSummary(domain);
    if (!summary || summary.domain !== domain || !Number.isInteger(Number(summary.totalApproved)) ||
      typeof summary.categoryCounts !== "object" || !Array.isArray(summary.recentReports)) {
      throw new CommunityError("bad_response", "Community reports are temporarily unavailable.", 503);
    }
    return res.json({
      domain,
      totalApproved: Number(summary.totalApproved),
      categoryCounts: summary.categoryCounts,
      recentReports: summary.recentReports,
      source: "community_reports",
      trust: "unverified_user_submissions",
      disclaimer: "These community submissions are user reports reviewed for publication; they are not independently verified threat findings and do not determine the security verdict."
    });
  } catch (error) { return reportFailure(res, error); }
});

router.post("/reports", async (req, res) => {
  let report;
  try { report = validateReport(req.body || {}); }
  catch (error) { return reportFailure(res, error); }
  try {
    const reporterHash = hashReporter(req.ip, process.env.COMMUNITY_HASH_SECRET);
    const result = await store.submitReport(report, {
      reporterHash,
      duplicateHash: hashForDuplicate(report)
    });
    if (!result || result.status !== "pending" || typeof result.id !== "string") {
      return res.status(503).json({ error: "Community reports are temporarily unavailable.", code: "bad_response" });
    }
    return res.status(202).json({
      id: result.id,
      domain: report.domain,
      status: "pending",
      submittedAt: result.submittedAt,
      message: "Report received for moderation. It will not appear in public results unless approved."
    });
  } catch (error) { return reportFailure(res, error); }
});

router.get("/admin/reports", requireAdmin, async (req, res) => {
  try {
    const reports = await store.getModerationQueue();
    if (!Array.isArray(reports)) throw new CommunityError("bad_response", "Moderation queue is unavailable.", 503);
    return res.json({ reports });
  } catch (error) { return reportFailure(res, error); }
});

router.post("/admin/reports/:id/moderation", requireAdmin, async (req, res) => {
  const id = req.params.id;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    return res.status(400).json({ error: "A valid report ID is required." });
  }
  const action = req.body?.action;
  if (!(["approve", "reject", "remove"].includes(action))) {
    return res.status(400).json({ error: "Action must be approve, reject, or remove." });
  }
  try {
    const result = await store.moderateReport(id, action);
    if (!result || result.status !== (action === "remove" ? "removed" : action === "approve" ? "approved" : "rejected")) {
      throw new CommunityError("bad_response", "Moderation action could not be confirmed.", 503);
    }
    return res.json(result);
  } catch (error) { return reportFailure(res, error); }
});

module.exports = router;
