"use strict";
(function (root) {
  const labels = {
    known_threat_detected: "Known threat detected",
    suspicious_indicators: "Suspicious indicators found",
    no_known_threats_found: "No known threats found",
    inconclusive: "Inconclusive",
    trusted_official_domain: "Verified official domain"
  };

  function safeArray(value) { return Array.isArray(value) ? value.filter((item) => item && typeof item === "object") : []; }
  function analyze(data = {}, communitySummary) {
    const verdict = data && typeof data.verdict === "object" && data.verdict ? data.verdict : {};
    const identity = data && typeof data.domainImpersonation === "object" && data.domainImpersonation ? data.domainImpersonation : {};
    const threat = data && typeof data.threatAssessment === "object" && data.threatAssessment ? data.threatAssessment : {};
    const findings = safeArray(data?.urlSignals?.findings);
    const evidence = safeArray(data?.evidence);
    const providers = [...safeArray(data?.providers), ...safeArray(threat.providers)];
    const status = typeof verdict.status === "string" ? verdict.status : "inconclusive";
    const lookalike = identity.status === "possible_lookalike";
    const threatFound = threat.status === "reported" || providers.some((provider) => provider.id === "google_safe_browsing" && provider.status === "reported");
    const relevantEvidence = evidence.filter((entry) => entry.category === "domain_specific");
    let explanation;
    let recommendation;
    if (threatFound || status === "known_threat_detected") {
      explanation = "A configured reputation check reported a threat match for this URL.";
      recommendation = "Avoid interacting with this website. Do not download files or connect a wallet.";
    } else if (lookalike) {
      explanation = "This domain resembles a verified official website. Its identity has not been established.";
      recommendation = "Do not connect your wallet or enter credentials. Navigate to the independently verified official domain instead.";
    } else if (identity.status === "official_domain" || identity.status === "official_subdomain" || status === "trusted_official_domain") {
      explanation = identity.status === "official_subdomain"
        ? "This subdomain is within a curated, verified official domain. That does not verify every page or linked service."
        : "The domain matches a curated, verified official domain. That does not verify every page or linked service.";
      recommendation = "Domain identity matches a curated verified entry, but review the specific page and any downloads or linked services before trusting them.";
    } else if (status === "no_known_threats_found") {
      explanation = "Configured checks found no known threat. This does not establish that the website is legitimate or safe.";
      recommendation = "Continue with normal caution. Verify the website's identity before entering credentials or connecting a wallet.";
    } else if (status === "suspicious_indicators") {
      explanation = "URL structure checks found indicators that deserve review; they do not prove malicious activity.";
      recommendation = "Avoid sensitive interactions until you can independently verify the website and understand the flagged URL indicators.";
    } else {
      explanation = "Not enough reliable evidence was available to reach a meaningful conclusion.";
      recommendation = "Avoid sensitive interactions until the website's identity can be independently verified.";
    }

    let importantSignal = "No single supporting signal was available.";
    if (threatFound) importantSignal = "Reputation check reported a threat match for the submitted URL.";
    else if (findings.length) importantSignal = typeof findings[0]?.explanation === "string" ? findings[0].explanation : "URL structure indicators were returned for review.";
    else if (lookalike) importantSignal = `Possible similarity to ${typeof identity.matches?.[0]?.officialDomain === "string" ? identity.matches[0].officialDomain : "a curated official domain"}; similarity alone does not establish maliciousness.`;
    else if (identity.status === "official_domain" || identity.status === "official_subdomain") importantSignal = identity.status === "official_subdomain" ? "The registrable domain matches a curated official domain." : "The domain exactly matches a curated official domain.";
    else if (relevantEvidence.length) importantSignal = "Search returned evidence directly associated with the investigated hostname; search relevance does not prove ownership or legitimacy.";
    else if (evidence.length) importantSignal = "Only general or unclear search context was returned; it does not establish facts about this domain.";

    const identityState = identity.status === "official_domain" || identity.status === "official_subdomain"
      ? "Verified" : identity.status === "possible_lookalike" ? "Signal found"
        : identity.status === "no_match" ? "No match found"
          : identity.status === "unavailable" ? "Unavailable" : "Not checked";
    const reputationState = threat.status === "reported" || threatFound ? "Signal found"
      : threat.status === "no_match" ? "No match found" : threat.status === "unavailable" ? "Unavailable" : "Not checked";
    const checklist = [
      { label: "Official-domain identity", state: identityState, detail: identity.status === "official_subdomain" ? "Verified subdomain under a curated domain; individual page safety is not implied." : identity.status === "official_domain" ? "Exact match to a curated domain; this is not a guarantee of page safety." : identity.status === "possible_lookalike" ? "Similarity is an indicator, not proof of impersonation." : identity.status === "no_match" ? "No identity match in the curated reference set." : identity.status === "unavailable" ? "The identity check did not complete." : "No identity result was provided." },
      { label: "Threat reputation", state: reputationState, detail: threat.status === "reported" || threatFound ? "A provider reported a match for this URL." : threat.status === "no_match" ? "No match in the configured threat check; this does not prove safety." : threat.status === "unavailable" ? "The reputation check did not complete." : "No completed reputation result was provided." },
      { label: "URL structure", state: findings.length ? "Signal found" : Array.isArray(data?.urlSignals?.findings) ? "No match found" : "Unavailable", detail: findings.length ? `${findings.length} structural indicator(s) returned; indicators are not proof of maliciousness.` : Array.isArray(data?.urlSignals?.findings) ? "No configured URL-structure indicators were found." : "URL-structure result is missing or malformed." }
    ];
    const failedProviders = [...new Map(providers.filter((provider) => provider.status === "unavailable").map((provider) => [provider.id || provider.name || "provider", provider])).values()];
    if (failedProviders.length) checklist.push({ label: "Important providers", state: "Unavailable", detail: `${failedProviders.map((provider) => provider.name || provider.id || "Provider").join(", ")} did not complete.` });

    const contractRequested = data?.ethereumAssessment?.status !== undefined && data.ethereumAssessment.status !== "not_requested" || Boolean(data?.contractAnalysis);
    if (contractRequested) {
      const analyzed = data?.ethereumAssessment?.status === "available" || ["available", "incomplete"].includes(data?.contractAnalysis?.status);
      const unavailable = data?.ethereumAssessment?.status === "unavailable" || data?.contractAnalysis?.status === "unavailable";
      checklist.push({ label: "Contract analysis", state: unavailable ? "Unavailable" : analyzed ? "Verified" : "Not checked", detail: unavailable ? "A requested contract check was unavailable." : analyzed ? "The supplied address was analyzed; this does not establish whether it is safe or related to the website." : "A contract address was supplied, but no completed analysis was returned." });
    }
    if (communitySummary && Number.isInteger(communitySummary.totalApproved)) {
      const count = communitySummary.totalApproved;
      checklist.push({ label: "Approved community reports", state: count > 0 ? "Signal found" : "No match found", detail: count > 0 ? `${count} approved user report(s) add context only; they do not determine the security verdict.` : "No approved community reports were found. Reports are unverified submissions." });
    } else if (communitySummary?.status === "unavailable") {
      checklist.push({ label: "Approved community reports", state: "Unavailable", detail: "Community reports could not be loaded. This does not affect the security verdict or recommendation." });
    }
    return {
      verdictLabel: labels[status] || "Inconclusive",
      explanation,
      recommendation,
      importantSignal,
      attention: [
        threatFound ? "Reputation match reported" : null,
        lookalike ? "Possible lookalike" : null,
        failedProviders.length ? `${failedProviders.length} provider check(s) unavailable` : null,
        contractRequested && checklist.some((item) => item.label === "Contract analysis" && item.state === "Unavailable") ? "Contract analysis unavailable" : null,
        communitySummary?.status === "unavailable" ? "Community reports unavailable" : communitySummary?.totalApproved > 0 ? `${communitySummary.totalApproved} approved community report(s)` : null
      ].filter(Boolean),
      checklist,
      evidenceGroup: relevantEvidence.length ? "domain_specific" : evidence.length ? "general_context" : "none"
    };
  }

  function render(data, documentRef = root.document, communitySummary) {
    const model = analyze(data, communitySummary);
    const panel = documentRef.getElementById("action-center");
    if (!panel) return model;
    panel.hidden = false;
    documentRef.getElementById("action-verdict").textContent = model.verdictLabel;
    documentRef.getElementById("action-explanation").textContent = model.explanation;
    documentRef.getElementById("action-recommendation").textContent = model.recommendation;
    documentRef.getElementById("action-signal").textContent = model.importantSignal;
    const attention = documentRef.getElementById("action-attention");
    attention.replaceChildren();
    model.attention.forEach((message) => { const item = documentRef.createElement("li"); item.textContent = message; attention.append(item); });
    const checklist = documentRef.getElementById("action-checklist");
    checklist.replaceChildren();
    model.checklist.forEach((entry) => {
      const item = documentRef.createElement("li");
      item.className = "action-check-item";
      const label = documentRef.createElement("strong"); label.textContent = entry.label;
      const state = documentRef.createElement("span"); state.className = "action-state"; state.dataset.state = entry.state.toLowerCase().replaceAll(" ", "-"); state.textContent = entry.state;
      const detail = documentRef.createElement("p"); detail.textContent = entry.detail;
      item.append(label, state, detail); checklist.append(item);
    });
    const attentionBlock = documentRef.getElementById("action-attention-block");
    attentionBlock.hidden = model.attention.length === 0;
    return model;
  }
  root.ChainShieldActionCenter = { analyze, render };
})(typeof window !== "undefined" ? window : globalThis);
