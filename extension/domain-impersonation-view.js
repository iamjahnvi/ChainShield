"use strict";
(function (root) {
  function element(documentRef, tagName, className, text) {
    const node = documentRef.createElement(tagName);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function safeHttpUrl(value) {
    if (typeof value !== "string") return null;
    try {
      const parsed = new URL(value);
      return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
    } catch { return null; }
  }

  function render(data, documentRef = root.document) {
    const panel = documentRef.getElementById("results-impersonation");
    const content = documentRef.getElementById("impersonation-content");
    const status = documentRef.getElementById("impersonation-status");
    const result = data?.domainImpersonation;
    panel.hidden = false;
    content.replaceChildren();
    const labels = { official_domain: "Official domain match", official_subdomain: "Official subdomain", possible_lookalike: "Possible lookalike", no_match: "No match in curated reference set", inconclusive: "Inconclusive", detected: "Similarity detected", unknown: "Inconclusive", unavailable: "Check unavailable" };
    status.textContent = result && typeof result === "object"
      ? `${labels[result.status] || "Inconclusive"}. ${result.explanation || "No explanation was provided."}`
      : "This check was unavailable in the investigation response.";
    (Array.isArray(result?.matches) ? result.matches : []).forEach((match) => {
      const row = element(documentRef, "article", "signal-item");
      row.append(element(documentRef, "div", "signal-title", `${match.officialName || "Official service"} · ${match.officialDomain || "domain unavailable"}`));
      row.append(element(documentRef, "p", "evidence-snippet", match.reason || "Similarity reason unavailable."));
      if (match.provenance) row.append(element(documentRef, "p", "evidence-meta", `Provenance: ${match.provenance}`));
      const meta = [
        match.verificationStatus ? `Verification: ${match.verificationStatus}` : null,
        match.domainRole ? `Domain role: ${match.domainRole}${match.redirectTarget ? ` to ${match.redirectTarget}` : ""}` : null,
        match.verifiedAt ? `Reviewed: ${match.verifiedAt}` : null,
        match.confidence ? `Similarity confidence: ${match.confidence}` : null
      ].filter(Boolean);
      if (meta.length) row.append(element(documentRef, "p", "evidence-meta", meta.join(" · ")));
      const sources = Array.isArray(match.sources) ? match.sources : match.source ? [{ url: match.source }] : [];
      sources.forEach((reference) => {
        const source = safeHttpUrl(reference?.url);
        if (!source) return;
        const link = element(documentRef, "a", "evidence-link", `Verification source: ${new URL(source).hostname}`);
        link.href = source; link.target = "_blank"; link.rel = "noopener noreferrer";
        row.append(link);
      });
      content.append(row);
    });
  }

  root.renderDomainImpersonation = render;
  root.ChainShieldDomainImpersonationView = { render, safeHttpUrl };
})(typeof window !== "undefined" ? window : globalThis);
