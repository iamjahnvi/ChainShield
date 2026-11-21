"use strict";

(function () {
  const REPORT_CATEGORIES = ["phishing", "impersonation", "crypto_scam", "fake_airdrop", "malicious_wallet_connection", "suspicious_investment_platform", "other"];
  const section = document.getElementById("results-community");
  const status = document.getElementById("community-status");
  const summary = document.getElementById("community-summary");
  const reports = document.getElementById("community-reports");
  const openButton = document.getElementById("community-report-open");
  const form = document.getElementById("community-report-form");
  const formStatus = document.getElementById("community-form-status");
  const submitButton = document.getElementById("community-report-submit");
  let activeDomain = "";
  let apiBase = "";

  function element(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }

  function categoryLabel(category) {
    const labels = {
      phishing: "Phishing", impersonation: "Impersonation", crypto_scam: "Crypto scam",
      fake_airdrop: "Fake airdrop", malicious_wallet_connection: "Malicious wallet connection",
      suspicious_investment_platform: "Suspicious investment platform", other: "Other"
    };
    return labels[category] || "Other";
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? date.toLocaleDateString() : "Date unavailable";
  }

  function render(data) {
    summary.replaceChildren();
    reports.replaceChildren();
    status.textContent = `${data.totalApproved} approved community report${data.totalApproved === 1 ? "" : "s"} for ${data.domain}.`;
    const categories = Object.entries(data.categoryCounts || {}).filter(([, count]) => Number(count) > 0);
    if (categories.length) {
      const breakdown = element("p", "evidence-meta", categories.map(([category, count]) => `${categoryLabel(category)}: ${count}`).join(" · "));
      summary.append(breakdown);
    }
    if (!data.recentReports.length) {
      reports.append(element("p", "community-empty", "No community reports yet."));
      announceCommunity(data);
      return;
    }
    data.recentReports.forEach((report) => {
      const item = element("article", "evidence-item");
      item.append(element("div", "evidence-title", categoryLabel(report.category)));
      item.append(element("p", "evidence-snippet", report.description));
      item.append(element("p", "evidence-meta", `Approved report · ${formatDate(report.submittedAt)}`));
      if (typeof report.evidenceUrl === "string") item.append(element("p", "evidence-meta", `Submitted evidence link (not opened by ChainShield): ${report.evidenceUrl}`));
      reports.append(item);
    });
    announceCommunity(data);
  }

  function announceCommunity(data) {
    if (typeof window.dispatchEvent === "function" && typeof CustomEvent === "function") {
      window.dispatchEvent(new CustomEvent("chainshield:community-update", { detail: data }));
    }
  }

  async function request(url, options) {
    const response = await fetch(url, { credentials: "omit", cache: "no-store", redirect: "error", ...options });
    let data;
    try { data = await response.json(); } catch { throw new Error("Community service returned an unreadable response."); }
    if (!response.ok) throw new Error(data?.error || "Community service is temporarily unavailable.");
    return data;
  }

  async function load() {
    status.textContent = "Loading community reports…";
    summary.replaceChildren();
    reports.replaceChildren();
    try {
      const data = await request(`${apiBase}/community/domains/${encodeURIComponent(activeDomain)}`);
      if (!data || data.source !== "community_reports" || data.trust !== "unverified_user_submissions" ||
        !Number.isInteger(data.totalApproved) || !data.categoryCounts || !Array.isArray(data.recentReports) ||
        data.recentReports.some((report) => !report || typeof report.description !== "string" || !REPORT_CATEGORIES.includes(report.category))) {
        throw new Error("Community service returned an incomplete response.");
      }
      render(data);
    } catch (error) {
      status.textContent = "Community reports are temporarily unavailable. The security assessment is unaffected.";
      reports.append(element("p", "community-error", error.message || "Try again later."));
      announceCommunity({ status: "unavailable" });
    }
  }

  window.initializeCommunityIntelligence = function initializeCommunityIntelligence(domain, base) {
    activeDomain = typeof domain === "string" ? domain : "";
    apiBase = String(base || "").replace(/\/$/, "");
    section.hidden = false;
    form.hidden = true;
    form.reset();
    formStatus.textContent = "";
    load();
  };

  openButton.addEventListener("click", () => {
    form.hidden = !form.hidden;
    if (!form.hidden) document.getElementById("community-category").focus();
  });
  document.getElementById("community-report-cancel").addEventListener("click", () => {
    form.hidden = true;
    formStatus.textContent = "";
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submitButton.disabled) return;
    submitButton.disabled = true;
    formStatus.textContent = "Submitting for moderation…";
    try {
      const data = await request(`${apiBase}/community/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: activeDomain,
          category: document.getElementById("community-category").value,
          description: document.getElementById("community-description").value,
          evidenceUrl: document.getElementById("community-evidence-url").value.trim() || undefined
        })
      });
      if (data.status !== "pending") throw new Error("The report status could not be confirmed.");
      form.reset();
      formStatus.textContent = data.message || "Report received and awaiting moderation.";
    } catch (error) {
      formStatus.textContent = error.message || "The report could not be submitted. Try again later.";
    } finally {
      submitButton.disabled = false;
    }
  });
})();
