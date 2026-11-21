"use strict";

(function () {
  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }

  function safeHttpUrl(value) {
    if (typeof value !== "string") return null;
    try {
      const parsed = new URL(value);
      return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
    } catch { return null; }
  }

  window.renderSafeAlternatives = function renderSafeAlternatives(alternatives) {
    const panel = document.getElementById("results-alternatives");
    const status = document.getElementById("results-alternatives-status");
    const list = document.getElementById("results-alternatives-list");
    panel.hidden = false;
    list.replaceChildren();
    const recommendations = Array.isArray(alternatives?.recommendations) ? alternatives.recommendations : [];
    if (recommendations.length === 0) {
      status.textContent = "No suitable alternatives could be verified from the available evidence.";
      list.append(node("p", "evidence-limit", "Website purpose may be unclear, or no matching listing from a trusted source was available."));
      return;
    }
    status.textContent = `Category: ${(alternatives.category || "unknown").replaceAll("_", " ")}; confidence ${Math.round((alternatives.categoryConfidence || 0) * 100)}%. Listing and domain verification do not guarantee service safety.`;
    const groups = new Map();
    recommendations.forEach((recommendation) => {
      const category = recommendation.category || alternatives.category || "unknown";
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(recommendation);
    });
    groups.forEach((items, category) => {
      const group = node("section", "alternative-group");
      group.append(node("h4", "alternative-group-heading", category.replaceAll("_", " ")));
      items.forEach((recommendation) => {
      const card = node("article", "evidence-item");
      card.append(node("div", "evidence-title", recommendation.name || "Alternative"));
      const href = recommendation.verificationStatus === "verified" ? safeHttpUrl(recommendation.officialUrl) : null;
      if (href) {
        const link = node("a", "evidence-link", `Official site: ${recommendation.officialDomain || new URL(href).hostname}`);
        link.href = href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        card.append(link);
      }
      card.append(node("p", "evidence-snippet", recommendation.description || ""));
      card.append(node("p", "evidence-meta", `Directory: ${recommendation.listingStatus || "not confirmed"} · Official domain: ${recommendation.verificationStatus || "unverified"}${recommendation.verifiedAt ? ` · Checked ${recommendation.verifiedAt}` : ""}`));
      card.append(node("p", "evidence-reason", recommendation.reason || "No verification reason was provided."));
      for (const [label, rawUrl] of [["Directory listing", recommendation.listingSource], ["Domain verification source", recommendation.verificationSource]]) {
        const sourceUrl = safeHttpUrl(rawUrl);
        if (!sourceUrl) continue;
        const source = node("a", "evidence-link", `${label}: ${new URL(sourceUrl).hostname}`);
        source.href = sourceUrl;
        source.target = "_blank";
        source.rel = "noopener noreferrer";
        card.append(source);
      }
      group.append(card);
      });
      list.append(group);
    });
  };
})();
