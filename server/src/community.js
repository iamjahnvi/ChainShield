"use strict";

const crypto = require("crypto");
const net = require("net");
const { getDomain } = require("tldts");

const REPORT_CATEGORIES = Object.freeze([
  "phishing",
  "impersonation",
  "crypto_scam",
  "fake_airdrop",
  "malicious_wallet_connection",
  "suspicious_investment_platform",
  "other"
]);

class CommunityError extends Error {
  constructor(code, message, status = 503) {
    super(message);
    this.name = "CommunityError";
    this.code = code;
    this.status = status;
  }
}

function registrableDomain(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host || net.isIP(host) || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".onion")) return null;
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => !label || label.length > 63)) return null;
  return getDomain(host, { allowPrivateDomains: true }) || null;
}

function normalizeDomain(input) {
  if (typeof input !== "string" || input.trim() === "" || input.length > 2048) {
    throw new CommunityError("invalid_domain", "Enter a public website domain or URL.", 400);
  }
  const raw = input.trim();
  let parsed;
  try {
    parsed = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    throw new CommunityError("invalid_domain", "Enter a valid public website domain or URL.", 400);
  }
  if (!(["http:", "https:"].includes(parsed.protocol)) || parsed.username || parsed.password) {
    throw new CommunityError("invalid_domain", "Only public HTTP or HTTPS website domains are accepted.", 400);
  }
  const domain = registrableDomain(parsed.hostname);
  if (!domain) throw new CommunityError("invalid_domain", "The submitted host is not a public registrable domain.", 400);
  return domain;
}

function normalizeDescription(value) {
  if (typeof value !== "string") throw new CommunityError("invalid_description", "A short report description is required.", 400);
  let text = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").replace(/\s+/g, " ").trim();
  text = text
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[email redacted]")
    .replace(/\b0x[a-f0-9]{40,64}\b/gi, "[wallet data redacted]")
    .replace(/\b(?:\+?\d[\d(). -]{7,}\d)\b/g, "[phone number redacted]")
    .replace(/\b(?:seed phrase|recovery phrase|mnemonic)\s*[:=]\s*(?:[a-z]+\s+){11,23}[a-z]+\b/gi, "[recovery phrase redacted]");
  if (text.length < 12 || text.length > 500) throw new CommunityError("invalid_description", "Description must be 12 to 500 characters.", 400);
  return text;
}

function normalizeEvidenceUrl(value) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > 2048) throw new CommunityError("invalid_evidence_url", "Evidence link must be an HTTPS URL under 2048 characters.", 400);
  let parsed;
  try { parsed = new URL(value); } catch { throw new CommunityError("invalid_evidence_url", "Evidence link must be a valid HTTPS URL.", 400); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || !registrableDomain(parsed.hostname)) {
    throw new CommunityError("invalid_evidence_url", "Evidence link must use HTTPS and a public domain.", 400);
  }
  parsed.search = "";
  parsed.hash = "";
  return parsed.href;
}

function validateReport(body = {}) {
  const domain = normalizeDomain(body.domain);
  if (!REPORT_CATEGORIES.includes(body.category)) throw new CommunityError("invalid_category", "Choose a supported report category.", 400);
  const description = normalizeDescription(body.description);
  const evidenceUrl = normalizeEvidenceUrl(body.evidenceUrl);
  return { domain, category: body.category, description, evidenceUrl };
}

function hashForDuplicate(report) {
  const normalizedDescription = String(report.description).normalize("NFKC").replace(/\s+/g, " ").trim().toLocaleLowerCase("en-US");
  return crypto.createHash("sha256").update(`${String(report.domain).toLowerCase()}\n${report.category}\n${normalizedDescription}`).digest("hex");
}

function hashReporter(ip, secret) {
  if (typeof secret !== "string" || secret.length < 32) throw new CommunityError("config_missing", "Community reporting is not configured.");
  const normalizedIp = typeof ip === "string" && ip.trim() ? ip.trim() : "unknown";
  return crypto.createHmac("sha256", secret).update(normalizedIp).digest("hex");
}

module.exports = {
  REPORT_CATEGORIES,
  CommunityError,
  registrableDomain,
  normalizeDomain,
  normalizeDescription,
  normalizeEvidenceUrl,
  validateReport,
  hashForDuplicate,
  hashReporter
};
