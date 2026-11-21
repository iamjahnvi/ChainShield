"use strict";
(function (root) {
  const KEY = "chainShieldInvestigationHistory";
  const LIMIT = 10;
  function validRecord(value) {
    return value && typeof value === "object" && typeof value.id === "string" &&
      typeof value.url === "string" && value.data && typeof value.data === "object" &&
      typeof value.timestamp === "string";
  }
  function read(storage = root.localStorage) {
    try {
      const parsed = JSON.parse(storage.getItem(KEY) || "[]");
      return Array.isArray(parsed) ? parsed.filter(validRecord).slice(0, LIMIT) : [];
    } catch { return []; }
  }
  function save(record, storage = root.localStorage) {
    if (!record || !validRecord(record)) return read(storage);
    const records = [record, ...read(storage).filter((item) => item.id !== record.id)].slice(0, LIMIT);
    try { storage.setItem(KEY, JSON.stringify(records)); } catch { /* quota/private mode: history is best effort */ }
    return records;
  }
  function clear(storage = root.localStorage) { try { storage.removeItem(KEY); } catch { /* storage may be unavailable */ } }
  function compare(left, right) {
    const a = left?.data || {}; const b = right?.data || {};
    const status = (item) => item.verdict?.status || "unknown";
    const providers = (item) => (Array.isArray(item.providers) ? item.providers : []).filter((p) => p && typeof p === "object").map((p) => `${p.id || "unknown"}:${p.status || "unknown"}`).sort().join("|");
    const findings = (item) => JSON.stringify(Array.isArray(item.urlSignals?.findings) ? item.urlSignals.findings : []);
    const impersonation = (item) => item.domainImpersonation?.status || "unknown";
    const evidence = (item) => JSON.stringify({ public: (Array.isArray(item.evidence) ? item.evidence : []).filter((entry) => entry && typeof entry === "object").map(({ title, url, snippet, category }) => ({ title, url, snippet, category })), threat: (Array.isArray(item.threatAssessment?.providers) ? item.threatAssessment.providers : []).filter(Boolean).map((provider) => ({ id: provider.id, matches: Array.isArray(provider.matches) ? provider.matches : [] })), contract: (Array.isArray(item.contractAnalysis?.layers) ? item.contractAnalysis.layers : []).filter(Boolean).map((layer) => ({ address: layer.address, status: layer.status, capabilities: layer.capabilities })) });
    return [
      { field: "Verdict", before: status(a), after: status(b) },
      { field: "Provider status", before: providers(a), after: providers(b) },
      { field: "Evidence", before: evidence(a), after: evidence(b) },
      { field: "URL indicators", before: findings(a), after: findings(b) },
      { field: "Domain similarity", before: impersonation(a), after: impersonation(b) }
    ].filter((item) => item.before !== item.after);
  }
  root.ChainShieldHistory = { KEY, LIMIT, read, save, clear, compare, validRecord };
})(typeof globalThis !== "undefined" ? globalThis : this);
