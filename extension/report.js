"use strict";
(function (root) {
  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  }
  function safeHttpUrl(value) {
    try {
      const parsed = new URL(value);
      if (!["http:", "https:"].includes(parsed.protocol)) return null;
      parsed.username = ""; parsed.password = ""; parsed.hash = "";
      for (const key of Array.from(parsed.searchParams.keys())) {
        if (/(token|key|secret|auth|session|password|signature|credential|code)/i.test(key)) parsed.searchParams.set(key, "[REDACTED]");
      }
      return parsed.href;
    }
    catch { return null; }
  }
  function sanitize(value, key = "") {
    if (/(secret|token|credential|api.?key|authorization|network.?hash|raw.?ip)/i.test(key)) return undefined;
    if (typeof value === "string") {
      if (/^https?:\/\//i.test(value)) return safeHttpUrl(value) || "[unsafe URL omitted]";
      return value;
    }
    if (Array.isArray(value)) return value.map((entry) => sanitize(entry)).filter((entry) => entry !== undefined);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, sanitize(child, childKey)]).filter(([, child]) => child !== undefined));
    return value;
  }
  function createReport(record) {
    const data = record?.data || {};
    return {
      generatedAt: new Date().toISOString(),
      mode: record?.demo ? "SIMULATED DEMO DATA" : "LIVE INVESTIGATION DATA",
      investigatedUrl: safeHttpUrl(record?.url) || "Invalid or unsupported URL",
      normalizedDomain: data.domain || "",
      investigatedAt: record?.timestamp || "",
      verdict: sanitize(data.verdict || null),
      actionCenter: root.ChainShieldActionCenter ? root.ChainShieldActionCenter.analyze(data, record?.communitySummary) : null,
      domainImpersonation: sanitize(data.domainImpersonation || { status: "not_available" }),
      providers: sanitize(Array.isArray(data.providers) ? data.providers : []),
      evidence: sanitize(Array.isArray(data.evidence) ? data.evidence : []),
      threatAssessment: sanitize(data.threatAssessment || null),
      urlSignals: sanitize(data.urlSignals || null),
      ethereumAssessment: sanitize(data.ethereumAssessment || null),
      contractAnalysis: sanitize(data.contractAnalysis || null),
      safeAlternatives: sanitize(data.safeAlternatives || null),
      nextSteps: ["Review each provider result and its status.", "Open evidence sources manually and verify the domain through trusted channels.", "Run a fresh investigation before acting on an old report."],
      limitations: ["A lack of known matches is not proof of safety.", "Evidence and historical results can become outdated.", "Similarity to a known domain is an indicator, not proof of impersonation."]
    };
  }
  function printableHtml(record) {
    const report = createReport(record);
    const evidence = report.evidence.map((item) => {
      const link = safeHttpUrl(item.url);
      return `<li><strong>${escapeHtml(item.title || "Untitled source")}</strong><p>${escapeHtml(item.snippet || "")}</p>${link ? `<p>Source: <a rel="noreferrer noopener" href="${escapeHtml(link)}">${escapeHtml(link)}</a></p>` : ""}</li>`;
    }).join("");
    const providers = report.providers.map((provider) => `<li><strong>${escapeHtml(provider.name || provider.id || "Provider")}</strong>: ${escapeHtml(provider.status || "unknown")}</li>`).join("");
    const blockchain = [report.ethereumAssessment, report.contractAnalysis].filter(Boolean).map((item) => `<li>${escapeHtml(JSON.stringify(item))}</li>`).join("");
    const impersonation = report.domainImpersonation;
    const action = report.actionCenter || {};
    const checklist = Array.isArray(action.checklist) ? action.checklist.map((item) => `<li><strong>${escapeHtml(item.label)}: ${escapeHtml(item.state)}</strong> — ${escapeHtml(item.detail)}</li>`).join("") : "";
    const candidate = Array.isArray(impersonation.matches) ? impersonation.matches.map((match) => `<li>${escapeHtml(match.officialName)} (${escapeHtml(match.officialDomain)}): ${escapeHtml(match.reason)}; source ${escapeHtml(match.source)}</li>`).join("") : "";
    return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>ChainShield Investigation Report</title><style>body{font:15px/1.5 system-ui,sans-serif;max-width:850px;margin:2rem auto;padding:0 1rem;color:#17212b}h1,h2{line-height:1.2}section{border-top:1px solid #ccd4da;padding:1rem 0}li{margin:.6rem 0}a{overflow-wrap:anywhere}@media print{body{margin:0;max-width:none}a{color:#17212b}}</style><h1>ChainShield Investigation Report</h1><p><strong>${escapeHtml(report.mode)}</strong></p><p><b>URL:</b> ${escapeHtml(report.investigatedUrl)}<br><b>Domain:</b> ${escapeHtml(report.normalizedDomain)}<br><b>Investigated:</b> ${escapeHtml(report.investigatedAt)}</p><section><h2>Action Center</h2><h3>${escapeHtml(action.verdictLabel || report.verdict?.status || "Inconclusive")}</h3><p>${escapeHtml(action.explanation || report.verdict?.summary || "No verdict was returned.")}</p><p><strong>What to do:</strong> ${escapeHtml(action.recommendation || "Review the available evidence before interacting with this website.")}</p><p><strong>Most important signal:</strong> ${escapeHtml(action.importantSignal || "No single supporting signal was available.")}</p><h3>Before you interact</h3><ul>${checklist || "<li>No checklist data is available.</li>"}</ul><details><summary>Technical verdict details</summary><p>${escapeHtml(report.verdict?.summary || "No verdict detail was returned.")}</p><ul>${(report.verdict?.reasons || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></details></section><section><h2>Domain similarity</h2><p>${escapeHtml(impersonation.status || "unknown")}. ${escapeHtml(impersonation.explanation || "")}</p><ul>${candidate}</ul></section><section><h2>Provider checks</h2><ul>${providers || "<li>No provider results returned.</li>"}</ul></section><section><h2>Public evidence</h2><ul>${evidence || "<li>No public search evidence returned.</li>"}</ul></section><section><h2>Blockchain observations</h2><ul>${blockchain || "<li>No blockchain checks were requested.</li>"}</ul></section><section><h2>Next steps</h2><ul>${report.nextSteps.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section><section><h2>Limitations</h2><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul><p>Generated ${escapeHtml(report.generatedAt)}. Evidence links are user-initiated and open externally; this report does not embed remote content. Use the browser's Print command to save this report as PDF.</p></section></html>`;
  }
  function downloadJson(record) {
    const blob = new Blob([JSON.stringify(createReport(record), null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob); link.download = "chainshield-investigation.json";
    link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }
  function printReport(record) {
    const popup = root.open("", "_blank");
    if (!popup) return false;
    popup.opener = null;
    popup.document.open(); popup.document.write(printableHtml(record)); popup.document.close();
    popup.focus();
    popup.print();
    return true;
  }
  root.ChainShieldReport = { escapeHtml, safeHttpUrl, sanitize, createReport, printableHtml, downloadJson, printReport };
})(typeof window !== "undefined" ? window : globalThis);
