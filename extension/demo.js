"use strict";
(function (root) {
  const scenarios = Object.freeze({
    established: { url: "https://ethereum.org/", domain: "ethereum.org", verdict: "no_known_threats_found", tinyfish: "available", browsing: "no_match", impersonation: "no_match" },
    lookalike: { url: "https://metamaskk.io/", domain: "metamaskk.io", verdict: "suspicious_indicators", tinyfish: "unavailable", browsing: "no_match", impersonation: "possible_lookalike" },
    phishing: { url: "https://account-security-demo.invalid/verify-wallet/recovery", domain: "account-security-demo.invalid", verdict: "suspicious_indicators", tinyfish: "unavailable", browsing: "unavailable", impersonation: "no_match" },
    web3: { url: "https://uniswap.org/", domain: "uniswap.org", verdict: "no_known_threats_found", tinyfish: "available", browsing: "no_match", impersonation: "no_match", contract: "0x0000000000000000000000000000000000000001" },
    inconclusive: { url: "https://example.invalid/", domain: "example.invalid", verdict: "inconclusive", tinyfish: "unavailable", browsing: "unavailable", impersonation: "no_match" }
  });
  function createScenario(id) {
    const scenario = scenarios[id];
    if (!scenario) return null;
    const findings = id === "lookalike" ? [{ ruleId: "demo_lookalike", title: "Possible domain lookalike", severity: "low", explanation: "This deterministic demo illustrates how similarity is presented. It is not a live threat finding." }] : id === "phishing" ? [{ ruleId: "demo_phishing_style", title: "Fictional credential recovery path", severity: "low", explanation: "This reserved .invalid demo URL illustrates a suspicious page pattern. No live threat intelligence was queried." }] : [];
    const impersonation = scenario.impersonation === "possible_lookalike" ? {
      status: "possible_lookalike", candidateDomain: scenario.domain,
      explanation: "DEMO ONLY: simulated similarity result from a deterministic example; not a live verification.",
      matches: [{ officialName: "MetaMask", officialDomain: "metamask.io", source: "https://support.metamask.io/", reason: "Demo scenario uses a one-character label change.", confidence: "medium" }]
    } : { status: scenario.impersonation, candidateDomain: scenario.domain, matches: [], explanation: "DEMO ONLY: no live catalogue lookup was performed." };
    return {
      demo: true, status: "demo", summary: "Deterministic simulated scenario. No provider was contacted.", domain: scenario.domain, evidence: [], investigationType: "demo",
      providers: [{ id: "tinyfish_search", name: "TinyFish Search", status: scenario.tinyfish }, { id: "google_safe_browsing", name: "Google Safe Browsing", status: scenario.browsing }],
      verdict: { status: scenario.verdict, summary: `SIMULATED: ${scenario.verdict.replaceAll("_", " ")}.`, reasons: ["This result is generated locally for demonstration and is not a live security assessment."], evidenceReferences: [] },
      threatAssessment: { status: scenario.browsing, providers: [{ id: "google_safe_browsing", name: "Google Safe Browsing", status: scenario.browsing, matches: [] }] },
      urlSignals: { findings }, domainImpersonation: impersonation, safeAlternatives: { status: "unknown", alternatives: [], message: "No live recommendations are loaded in demo mode." },
      ethereumAssessment: scenario.contract ? { status: "unavailable", reason: "demo_not_requested", address: scenario.contract } : { status: "not_requested" },
      contractAnalysis: scenario.contract ? { status: "unavailable", reason: "Demo only. No blockchain or explorer request was made." } : undefined
    };
  }
  root.ChainShieldDemo = { scenarios, createScenario };
})(typeof globalThis !== "undefined" ? globalThis : this);
