const VERDICT_STATUSES = Object.freeze({
  KNOWN_THREAT_DETECTED: "known_threat_detected",
  TRUSTED_OFFICIAL_DOMAIN: "trusted_official_domain",
  SUSPICIOUS_INDICATORS: "suspicious_indicators",
  NO_KNOWN_THREATS_FOUND: "no_known_threats_found",
  INCONCLUSIVE: "inconclusive"
});

const NO_MATCH_LIMITATION =
  "Google Safe Browsing found no match for the checked URL among the configured threat types; this does not verify the website or prove it safe.";
const CLEAN_CHECK_LIMITATION =
  "No match was found in the completed Google Safe Browsing check, and the configured URL heuristics found no indicators. This is limited coverage, not a safety guarantee.";

function buildVerdict({ threatAssessment, urlSignals, providerStatuses = {} } = {}) {
  const evidenceReferences = [];
  const reasons = [];
  const threatProviders = Array.isArray(threatAssessment?.providers)
    ? threatAssessment.providers
    : [];
  const safeBrowsing = threatProviders.find(
    (provider) => provider && provider.id === "google_safe_browsing"
  );
  const matches = Array.isArray(safeBrowsing?.matches) ? safeBrowsing.matches : [];
  const findings = Array.isArray(urlSignals?.findings) ? urlSignals.findings : null;
  const safeBrowsingComplete =
    safeBrowsing?.status === "no_match" && Array.isArray(safeBrowsing.matches);
  const tinyFishComplete = providerStatuses.tinyfish === "available";
  const safeBrowsingFailed =
    providerStatuses.safeBrowsing === "unavailable" ||
    safeBrowsing?.status === "unavailable" ||
    !safeBrowsing;
  const malformedUrlSignals = findings === null;

  if (matches.length > 0 || safeBrowsing?.status === "reported") {
    const threatMatches = matches.length > 0 ? matches : [];
    threatMatches.forEach((match, index) => {
      evidenceReferences.push({
        source: "google_safe_browsing",
        type: "threat_match",
        index,
        threatType: match.threatType,
        matchedUrl: match.matchedUrl
      });
    });
    reasons.push("Google Safe Browsing reported a threat match for the submitted URL.");
    if (!tinyFishComplete) {
      reasons.push("TinyFish research was unavailable or incomplete; its results do not alter the threat match.");
    }
    return {
      status: VERDICT_STATUSES.KNOWN_THREAT_DETECTED,
      summary: "Known threat detected. Google Safe Browsing reported a match for this URL.",
      reasons,
      evidenceReferences
    };
  }

  if (malformedUrlSignals) {
    reasons.push("URL heuristic findings were missing or malformed.");
    if (!safeBrowsingComplete && !safeBrowsingFailed) {
      reasons.push("A valid Google Safe Browsing result was not available.");
    } else if (safeBrowsingFailed) {
      reasons.push("Google Safe Browsing is unavailable or did not return a valid completed result.");
    }
    if (!tinyFishComplete) {
      reasons.push("TinyFish search did not complete successfully.");
    }
    return {
      status: VERDICT_STATUSES.INCONCLUSIVE,
      summary: "Inconclusive. URL heuristic results were missing or malformed.",
      reasons,
      evidenceReferences
    };
  }

  if (findings.length > 0) {
    findings.forEach((finding, index) => {
      evidenceReferences.push({
        source: "url_heuristics",
        type: "url_signal",
        index,
        ruleId: finding?.ruleId,
        severity: finding?.severity
      });
    });
    reasons.push(
      `${findings.length} configured URL-structure indicator${findings.length === 1 ? " was" : "s were"} found. These indicators are not proof of maliciousness.`
    );
    if (safeBrowsingComplete) {
      reasons.push(NO_MATCH_LIMITATION);
    } else {
      reasons.push("Google Safe Browsing did not complete successfully, so its result is unknown.");
    }
    if (!tinyFishComplete) {
      reasons.push("TinyFish research was unavailable or incomplete.");
    }
    return {
      status: VERDICT_STATUSES.SUSPICIOUS_INDICATORS,
      summary: "Suspicious indicators found. Review the signals; they do not prove malicious activity.",
      reasons,
      evidenceReferences
    };
  }

  if (safeBrowsingFailed || !safeBrowsingComplete || !tinyFishComplete) {
    if (safeBrowsingFailed) {
      reasons.push("Google Safe Browsing is unavailable or did not return a valid completed result.");
    } else if (!safeBrowsingComplete) {
      reasons.push("A valid Google Safe Browsing result was not available.");
    }
    if (!tinyFishComplete) {
      reasons.push("TinyFish search did not complete successfully; no search result is inferred from the failure.");
    }

    if (safeBrowsingComplete) {
      evidenceReferences.push({
        source: "google_safe_browsing",
        type: "no_match",
        scope: "submitted_url",
        limitation: NO_MATCH_LIMITATION
      });
    }
    return {
      status: VERDICT_STATUSES.INCONCLUSIVE,
      summary: "Inconclusive. One or more required checks did not provide a complete result.",
      reasons,
      evidenceReferences
    };
  }

  evidenceReferences.push({
    source: "google_safe_browsing",
    type: "no_match",
    scope: "submitted_url",
    limitation: NO_MATCH_LIMITATION
  });
  evidenceReferences.push({
    source: "url_heuristics",
    type: "no_findings",
    limitation: "Only the configured local URL-structure heuristics were evaluated."
  });
  evidenceReferences.push({
    source: "tinyfish_search",
    type: "research_completed",
    limitation: "Search relevance is investigative research and does not verify official-domain ownership or establish safety."
  });
  reasons.push(CLEAN_CHECK_LIMITATION);
  reasons.push("TinyFish search completed; its relevance categories are research classifications, not a threat verdict.");

  return {
    status: VERDICT_STATUSES.NO_KNOWN_THREATS_FOUND,
    summary: "No known threats found by the completed checks. This is not a safety guarantee or domain verification.",
    reasons,
    evidenceReferences
  };
}

module.exports = { VERDICT_STATUSES, buildVerdict };
