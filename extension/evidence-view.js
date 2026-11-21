"use strict";
(function (root) {
  function element(doc, tag, className, text) {
    const item = doc.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }
  function safeHttpUrl(value) {
    if (typeof value !== "string") return null;
    try { const parsed = new URL(value); return ["http:", "https:"].includes(parsed.protocol) ? parsed.href : null; }
    catch { return null; }
  }
  function render(data, doc = root.document) {
    const panel = doc.getElementById("results-website");
    const container = doc.getElementById("results-website-evidence");
    const status = doc.getElementById("results-website-status");
    panel.hidden = false;
    container.replaceChildren();
    status.textContent = data && typeof data.summary === "string" ? data.summary : "Website search completed.";
    const entries = Array.isArray(data?.evidence) ? data.evidence.filter((entry) => entry && typeof entry === "object" && !Array.isArray(entry)) : [];
    if (!entries.length) {
      container.append(element(doc, "p", "result-content", "No public search evidence was returned. This does not establish that the website is safe."));
      return;
    }
    const direct = entries.filter((entry) => entry.category === "domain_specific");
    const context = entries.filter((entry) => entry.category !== "domain_specific");
    if (!direct.length) container.append(element(doc, "p", "evidence-limit", "No useful domain-specific search evidence was identified. General search context does not establish facts about this website."));
    function appendEntry(entry, target) {
      const item = element(doc, "article", "evidence-item");
      item.append(element(doc, "div", "evidence-title", entry.title || "Untitled source"));
      const href = safeHttpUrl(entry.url);
      if (href) {
        const link = element(doc, "a", "evidence-link", href); link.href = href; link.target = "_blank"; link.rel = "noopener noreferrer"; item.append(link);
      } else if (typeof entry.url === "string" && entry.url) item.append(element(doc, "p", "evidence-meta", entry.url));
      if (typeof entry.snippet === "string" && entry.snippet) item.append(element(doc, "p", "evidence-snippet", entry.snippet));
      const category = { domain_specific: "Domain-specific", general_information: "General information", irrelevant_or_unclear: "Irrelevant or unclear" }[entry.category];
      const metadata = [category, entry.source && `Source: ${entry.source}`, Number.isInteger(entry.position) && `Position: ${entry.position}`, entry.siteName && `Site: ${entry.siteName}`].filter(Boolean);
      if (metadata.length) item.append(element(doc, "p", "evidence-meta", metadata.join(" · ")));
      const reason = typeof entry.categoryReason === "string" && entry.categoryReason
        ? entry.categoryReason
        : entry.category === "domain_specific"
          ? "Classified as directly related to the investigated hostname. Search relevance is not independent proof of ownership or legitimacy."
          : entry.category === "general_information"
            ? "General security context; this result does not establish facts about the investigated domain."
            : "This result was not classified as directly related to the investigated domain.";
      item.append(element(doc, "p", "evidence-reason", reason));
      target.append(item);
    }
    direct.forEach((entry) => appendEntry(entry, container));
    if (context.length) {
      const details = doc.createElement("details"); details.className = "contextual-evidence-details";
      details.append(element(doc, "summary", "", `General or unclear context (${context.length})`));
      const list = element(doc, "div", "contextual-evidence-list");
      context.forEach((entry) => appendEntry(entry, list));
      details.append(list); container.append(details);
    }
  }
  root.ChainShieldEvidenceView = { render, safeHttpUrl };
})(typeof window !== "undefined" ? window : globalThis);
