const API_BASE_URL = String(window.CHAINSHIELD_API_BASE_URL || "http://localhost:3000/api").replace(/\/$/, "");
const API_URL = `${API_BASE_URL}/investigations`;
const ONBOARDING_KEY = "chainShieldOnboardingComplete";
const INVESTIGATION_TARGET_KEY = "chainShieldInvestigationTarget";

const onboardingView = document.getElementById("onboarding-view");
const workspaceView = document.getElementById("workspace-view");
const onboardingSteps = Array.from(document.querySelectorAll(".onboarding-step"));
const stepCount = document.getElementById("step-count");
const progressTrack = document.querySelector(".progress-track");
const progressFill = document.getElementById("progress-fill");
const backButton = document.getElementById("back-step");
const nextButton = document.getElementById("next-step");
const openWorkspaceButton = document.getElementById("open-workspace");
const skipButton = document.getElementById("skip-onboarding");
const investigationForm = document.getElementById("investigation-form");
const urlInput = document.getElementById("url-input");
const submitButton = document.getElementById("investigate-button");
const formMessage = document.getElementById("form-message");
const results = document.getElementById("results");
const resultsWeb3 = document.getElementById("results-web3");
const newInvestigationButton = document.getElementById("new-investigation");
const investigationContext = document.getElementById("investigation-context");
const siteStatusBadge = document.getElementById("site-status-badge");
const contractAddressInput = document.getElementById("contract-address");
const historyList = document.getElementById("history-list");
let currentRecord = null;
window.addEventListener("chainshield:community-update", (event) => {
  if (currentRecord && !currentRecord.demo) {
    currentRecord.communitySummary = event.detail;
    window.ChainShieldActionCenter.render(currentRecord.data, document, event.detail);
  }
});

let currentStep = 1;
let requestInProgress = false;
let requestSequence = 0;
const investigationTarget = new URLSearchParams(location.search).get("target");
const activeWebsite = safeHttpUrl(investigationTarget);

function showStep(stepNumber) {
  currentStep = Math.min(Math.max(stepNumber, 1), onboardingSteps.length);
  onboardingSteps.forEach((step, index) => {
    const active = index + 1 === currentStep;
    step.classList.toggle("active", active);
    step.setAttribute("aria-hidden", String(!active));
  });

  const activeHeading = onboardingSteps[currentStep - 1].querySelector("h1, h2");
  onboardingView.setAttribute("aria-labelledby", activeHeading.id);
  clear(stepCount);
  stepCount.append(
    document.createTextNode(String(currentStep).padStart(2, "0")),
    element("span", "", `/ ${String(onboardingSteps.length).padStart(2, "0")}`)
  );
  progressTrack.setAttribute("aria-valuenow", String(currentStep));
  progressFill.style.width = `${(currentStep / onboardingSteps.length) * 100}%`;
  backButton.disabled = currentStep === 1;
  nextButton.hidden = currentStep === onboardingSteps.length;
  openWorkspaceButton.hidden = currentStep !== onboardingSteps.length;
}

function openWorkspace() {
  localStorage.setItem(ONBOARDING_KEY, "true");
  onboardingView.hidden = true;
  workspaceView.hidden = false;
  if (activeWebsite && !urlInput.value) {
    urlInput.value = activeWebsite;
  }
  if (!urlInput.value) urlInput.focus();
}

function setFormMessage(message, state = "") {
  formMessage.textContent = message;
  if (state) {
    formMessage.dataset.state = state;
  } else {
    delete formMessage.dataset.state;
  }
}

function element(tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  return node;
}

function clear(node) {
  node.replaceChildren();
}

function setResultStatus(id, message, tone = "") {
  const node = document.getElementById(id);
  node.textContent = message;
  if (tone) {
    node.dataset.tone = tone;
  } else {
    delete node.dataset.tone;
  }
}

function addRow(container, label, value) {
  if (value === undefined || value === null || value === "") {
    return;
  }
  const row = element("div", "ethereum-row");
  row.append(element("strong", "", label), element("span", "", value));
  container.append(row);
}

function safeHttpUrl(value) {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:"
      ? parsed.href
      : null;
  } catch {
    return null;
  }
}

function renderWebsiteResults(data) {
  window.ChainShieldEvidenceView.render(data, document);
}

function renderThreatAssessment(assessment) {
  const panel = document.getElementById("results-threat");
  const evidence = document.getElementById("results-threat-evidence");
  panel.hidden = false;
  clear(evidence);

  const status = assessment && assessment.status;
  const provider = Array.isArray(assessment?.providers)
    ? assessment.providers.find((entry) => entry && entry.id === "google_safe_browsing")
    : null;
  let message;

  if (status === "reported") {
    message = "Google Safe Browsing reported a threat match for this URL.";
  } else if (status === "no_match") {
    message = "Google Safe Browsing completed with no reported match. This does not verify the site's identity or guarantee safety.";
  } else if (status === "unavailable") {
    message = "The Google Safe Browsing check was unavailable. No conclusion can be drawn from this check.";
  } else {
    message = "The threat-reputation result is inconclusive.";
  }
  setResultStatus("results-threat-status", message, status === "reported" ? "warning" : "");

  const matches = Array.isArray(provider?.matches) ? provider.matches : [];
  if (matches.length > 0) {
    matches.forEach((match) => {
      const item = element("article", "signal-item");
      item.append(element("div", "signal-title", match.threatType || "Reported threat"));
      const matchUrl = safeHttpUrl(match.matchedUrl);
      if (matchUrl) {
        const link = element("a", "evidence-link", matchUrl);
        link.href = matchUrl;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        item.append(link);
      }
      evidence.append(item);
    });
  } else if (status === "reported") {
    evidence.append(element("p", "result-content", "A threat match was reported, but match details were not provided."));
  } else if (status === "unavailable") {
    const reason = typeof provider?.reason === "string" ? provider.reason : "";
    evidence.append(element("p", "result-content", reason
      ? `Provider check unavailable (${reason}).`
      : "Provider match details are unavailable."));
  }
}

function renderSiteStatus(verdict, assessment, urlSignals) {
  const status = assessment && assessment.status;
  const findings = Array.isArray(urlSignals?.findings) ? urlSignals.findings : null;
  const labels = {
    known_threat_detected: "Known threat detected",
    trusted_official_domain: "Trusted official-domain evidence found",
    suspicious_indicators: "Suspicious indicators found",
    no_known_threats_found: "No known threats found",
    inconclusive: "Inconclusive"
  };
  const label = labels[verdict?.status] || (
    status === "reported"
      ? "Known threat detected"
      : findings && findings.length > 0
        ? "Suspicious indicators found"
        : status === "no_match"
          ? "No known threats reported"
          : status === "unavailable"
            ? "Threat check unavailable"
            : "Inconclusive"
  );
  const tone = verdict?.status === "known_threat_detected" || status === "reported"
    ? "error"
    : verdict?.status === "suspicious_indicators" || (findings && findings.length > 0)
      ? "warning"
      : "warning";
  const explanation = Array.isArray(verdict?.reasons) && verdict.reasons.length > 0
    ? verdict.reasons.join(" ")
    : verdict?.summary || "The available checks do not support a reliable overall conclusion.";

  siteStatusBadge.textContent = label;
  siteStatusBadge.dataset.tone = tone;
  siteStatusBadge.title = explanation;
  siteStatusBadge.setAttribute("aria-label", `${label}. ${explanation}`);
}

function renderUrlSignals(urlSignals) {
  const panel = document.getElementById("results-url");
  const content = document.getElementById("results-url-evidence");
  panel.hidden = false;
  clear(content);
  if (!Array.isArray(urlSignals?.findings)) {
    setResultStatus("results-url-status", "URL-structure checks are not configured.", "warning");
    content.append(element("p", "result-content", "No configured local checks were available for this investigation."));
    return;
  }

  const findings = urlSignals.findings;
  if (findings.length === 0) {
    setResultStatus("results-url-status", "No suspicious patterns detected by the configured checks.");
    content.append(element("p", "result-content", "These selected local checks do not establish that a URL is safe."));
    return;
  }

  setResultStatus("results-url-status", `${findings.length} URL-structure signal${findings.length === 1 ? "" : "s"} returned.`, "warning");
  findings.forEach((finding) => {
    const item = element("article", "signal-item");
    item.append(element("div", "signal-title", finding.title || finding.ruleId || "URL signal"));
    if (finding.severity) {
      item.append(element("span", "signal-observed", `Severity: ${finding.severity}`));
    }
    if (finding.explanation || finding.description) {
      item.append(element("p", "evidence-snippet", finding.explanation || finding.description));
    }
    if (finding.observedFeature && typeof finding.observedFeature === "object") {
      const { label, value } = finding.observedFeature;
      if (label || value) {
        item.append(element("p", "signal-observed", [label, value].filter(Boolean).join(": ")));
      }
    } else if (finding.evidence) {
      item.append(element("p", "signal-observed", finding.evidence));
    }
    content.append(item);
  });
}

function renderEthereumAssessment(assessment) {
  const panel = document.getElementById("results-ethereum");
  const content = document.getElementById("results-ethereum-evidence");
  panel.hidden = false;
  clear(content);
  const status = assessment && assessment.status;
  const tone = status === "available" ? "" : "warning";
  if (!assessment || typeof assessment !== "object") {
    setResultStatus("results-ethereum-status", "Ethereum RPC assessment is unavailable.", tone);
    content.append(element("p", "result-content", "No network or bytecode observations were returned."));
    return;
  }
  setResultStatus(
    "results-ethereum-status",
    status === "available"
      ? "Read-only Ethereum RPC observations are available."
      : `Ethereum RPC assessment is ${status || "unavailable"}${assessment.reason ? ` (${assessment.reason})` : ""}.`,
    tone
  );

  addRow(content, "Address", assessment.address);
  addRow(content, "Chain ID", assessment.chainId);
  addRow(content, "Latest block", assessment.latestBlock);
  if (assessment.codeStatus === "bytecode_present") {
    addRow(content, "Bytecode", "Present at the queried address");
  } else if (assessment.codeStatus === "no_bytecode") {
    addRow(content, "Bytecode", "No bytecode returned");
    content.append(element("p", "evidence-meta", "No bytecode alone does not prove this is an externally owned account; it may also reflect an undeployed address or network context."));
  }
}

const STATUS_LABELS = {
  available: "Available",
  incomplete: "Incomplete",
  unavailable: "Unavailable",
  unverified: "Unverified",
  unsupported_chain: "Unsupported chain",
  malformed: "Malformed response",
  cycle: "Cycle detected",
  hop_limit: "Hop limit reached"
};

function renderCapabilities(container, capabilities) {
  if (!Array.isArray(capabilities) || capabilities.length === 0) {
    return;
  }
  const list = element("ul", "capability-list");
  capabilities.forEach((capability) => {
    const item = element("li", "capability-item");
    item.append(element("div", "capability-name", capability.name || "Capability indicator"));
    const state = element("span", "capability-state", capability.status || "unknown");
    if (["detected", "unknown"].includes(capability.status)) {
      state.dataset.status = capability.status;
    }
    item.append(state);
    if (Array.isArray(capability.evidence)) {
      capability.evidence.forEach((evidence) => {
        item.append(element("p", "capability-evidence", evidence));
      });
    }
    if (capability.explanation) {
      item.append(element("p", "capability-evidence", capability.explanation));
    }
    if (capability.limitation) {
      item.append(element("p", "capability-limit", capability.limitation));
    }
    list.append(item);
  });
  container.append(list);
}

function renderContractAnalysis(analysis) {
  const panel = document.getElementById("results-contract");
  const web3Panel = document.getElementById("results-web3");
  const content = document.getElementById("results-contract-evidence");
  web3Panel.hidden = false;
  panel.hidden = false;
  clear(content);
  if (!analysis) {
    setResultStatus("results-contract-status", "Verified source analysis is unavailable.", "warning");
    content.append(element("p", "result-content", "No source analysis was returned for the submitted contract address."));
    return;
  }
  const statusText = STATUS_LABELS[analysis.status] || analysis.status || "Unknown";
  const tone = analysis.status === "available" ? "" : "warning";
  setResultStatus(
    "results-contract-status",
    `${statusText}${analysis.network ? ` · ${analysis.network}` : ""}${analysis.chainId ? ` · chain ID ${analysis.chainId}` : ""}`,
    tone
  );
  if (analysis.message) {
    content.append(element("p", "analysis-reason", analysis.message));
  }
  if (analysis.reason) {
    content.append(element("p", "evidence-meta", `Stopping or limitation reason: ${analysis.reason}`));
  }
  if (analysis.status === "unsupported_chain") {
    content.append(element("p", "result-content", "Source analysis is currently limited to Ethereum Mainnet. The network could not be treated as supported based on the submitted address alone."));
  }
  if (analysis.status === "unavailable" && analysis.reason === "rpc_chain_unavailable") {
    content.append(element("p", "result-content", "The RPC network check did not confirm a chain, so source analysis was not attempted."));
  }

  if (!Array.isArray(analysis.layers) || analysis.layers.length === 0) {
    if (analysis.sourceVerified === false || analysis.status === "unverified") {
      content.append(element("p", "result-content", "Verified source was not available for the submitted address."));
    }
    return;
  }

  analysis.layers.forEach((layer, index) => {
    const layerCard = element("article", "contract-layer");
    const heading = element("div", "layer-heading");
    const identity = element("div");
    identity.append(
      element("h4", "", layer.contractName || (index === 0 ? "Submitted contract" : `Implementation layer ${index}`)),
      element("p", "layer-address", layer.address || "Address unavailable")
    );
    heading.append(identity);

    const badges = element("div", "layer-badges");
    const statusBadge = element("span", "status-badge", STATUS_LABELS[layer.status] || layer.status || "Unknown");
    statusBadge.dataset.tone = layer.status === "available"
      ? "good"
      : ["unavailable", "malformed"].includes(layer.status)
        ? "error"
        : "warning";
    badges.append(statusBadge);
    const proxyLabel = layer.proxyStatus === "proxy"
      ? "Proxy"
      : layer.proxyStatus === "not_proxy"
        ? "Not identified as proxy"
        : layer.proxyStatus || "Proxy status unknown";
    badges.append(element("span", "status-badge", proxyLabel));
    const verifiedLabel = layer.sourceVerified === true
      ? "Source verified"
      : layer.sourceVerified === false
        ? "Source unverified"
        : "Verification unknown";
    badges.append(element("span", "status-badge", verifiedLabel));
    heading.append(badges);
    layerCard.append(heading);

    const meta = element("div", "layer-meta");
    if (layer.reason) {
      meta.append(element("span", "", `Reason: ${layer.reason}`));
    }
    if (layer.implementationAddress) {
      layerCard.append(
        element("p", "layer-next", `Explorer-reported next implementation: ${layer.implementationAddress}`)
      );
    }
    layerCard.append(meta);
    renderCapabilities(layerCard, layer.capabilities);
    content.append(layerCard);
  });
}

function renderEvidenceExplorer(data) {
  const panel = document.getElementById("results-explorer");
  const container = document.getElementById("provider-explorer");
  panel.hidden = false; clear(container);
  const statusMap = new Map((Array.isArray(data.providers) ? data.providers : []).map((provider) => [provider.id, provider]));
  const entries = [
    { id: "url_heuristics", name: "URL heuristics", status: Array.isArray(data.urlSignals?.findings) ? (data.urlSignals.findings.length ? "suspicious indicator" : "no match found") : "inconclusive", detail: data.urlSignals?.findings?.map((finding) => finding.explanation || finding.title).filter(Boolean).join(" ") || "Configured local URL-structure checks." },
    { id: "google_safe_browsing", name: "Google Safe Browsing", status: data.threatAssessment?.status || statusMap.get("google_safe_browsing")?.status || "unavailable", detail: data.threatAssessment?.status === "reported" ? "Provider returned a threat match." : data.threatAssessment?.status === "no_match" ? "No match for configured threat types; this does not verify safety." : "No completed reputation result is available." },
    { id: "tinyfish_search", name: "TinyFish public web evidence", status: statusMap.get("tinyfish_search")?.status || "unavailable", detail: data.summary || "No search summary returned." },
    { id: "domain_impersonation", name: "Domain impersonation", status: data.domainImpersonation?.status || "unavailable", detail: data.domainImpersonation?.explanation || "No similarity analysis returned." },
    { id: "ethereum_rpc", name: "Ethereum RPC", status: data.ethereumAssessment?.status === "not_requested" ? "not applicable" : data.ethereumAssessment?.status || "unavailable", detail: data.ethereumAssessment?.reason || data.ethereumAssessment?.codeStatus || "Explicit contract address required." },
    { id: "etherscan", name: "Etherscan source analysis", status: data.contractAnalysis?.status || "not applicable", detail: data.contractAnalysis?.message || data.contractAnalysis?.reason || "Not requested or no source result returned." }
  ];
  entries.forEach((entry) => {
    const row = element("article", "provider-row");
    row.append(element("div", "provider-row-heading", entry.name), element("span", "status-badge", entry.status));
    row.append(element("p", "evidence-meta", entry.detail));
    container.append(row);
  });
}

function renderResults(data, submittedUrl, options = {}) {
  document.getElementById("demo-banner").hidden = !options.demo;
  document.getElementById("historical-banner").hidden = !options.historical;
  document.getElementById("results-community").hidden = Boolean(options.demo);
  clear(investigationContext);
  const context = element("span");
  context.append(element("strong", "", "Website: "), document.createTextNode(submittedUrl));
  investigationContext.append(context);
  renderWebsiteResults(data);
  renderThreatAssessment(data.threatAssessment);
  renderUrlSignals(data.urlSignals);
  renderSiteStatus(data.verdict, data.threatAssessment, data.urlSignals);
  window.ChainShieldActionCenter.render(data);
  renderDomainImpersonation(data);
  renderEvidenceExplorer(data);
  window.renderSafeAlternatives(data.safeAlternatives);
  if (!options.demo) window.initializeCommunityIntelligence(data.domain, API_BASE_URL);
  renderEthereumAssessment(data.ethereumAssessment);
  if (data.contractAnalysis) {
    renderContractAnalysis(data.contractAnalysis);
    resultsWeb3.hidden = false;
  }
  results.hidden = false;
  currentRecord = { id: `${Date.now()}-${Math.random().toString(36).slice(2)}`, url: submittedUrl, timestamp: new Date().toISOString(), data, demo: Boolean(options.demo) };
  if (!options.demo && !options.historical) {
    try { window.ChainShieldHistory.save(currentRecord); renderHistory(); } catch { /* local history is optional */ }
  }
}

function renderHistory() {
  if (!historyList) return;
  clear(historyList);
  const records = window.ChainShieldHistory.read();
  if (!records.length) { historyList.append(element("p", "history-note", "No local investigations saved yet.")); return; }
  records.forEach((record) => {
    const row = element("div", "history-item");
    const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.value = record.id; checkbox.className = "history-select";
    checkbox.setAttribute("aria-label", `Select ${record.data.verdict?.status || "unknown"} investigation from ${record.timestamp} for comparison`);
    const copy = element("span", "", `${new Date(record.timestamp).toLocaleString()} · ${record.data.verdict?.status || "unknown"}${record.demo ? " · DEMO" : ""}`);
    const open = element("button", "button button-quiet history-open", "Open snapshot"); open.type = "button"; open.addEventListener("click", () => { urlInput.value = record.url; renderResults(record.data, record.url, { historical: true, demo: record.demo }); });
    row.append(checkbox, copy, open); historyList.append(row);
  });
}

function validateSubmission(submittedUrl, contractAddress) {
  // If a contract address is provided, we still need a URL but can be more lenient
  if (contractAddress && contractAddress.trim() !== "") {
    // Validate contract address format
    if (!/^0x[a-fA-F0-9]{40}$/.test(contractAddress.trim())) {
      return { message: "Contract address must be a 40-character hexadecimal string starting with 0x.", field: contractAddressInput };
    }
  }

  // URL is always required
  let parsedUrl;
  try {
    parsedUrl = new URL(submittedUrl);
  } catch {
    return { message: "Enter a valid HTTP or HTTPS website URL.", field: urlInput };
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return { message: "Only HTTP and HTTPS website URLs are supported.", field: urlInput };
  }
  return null;
}

async function investigate(event) {
  event.preventDefault();
  if (requestInProgress) {
    return;
  }

  const submittedUrl = urlInput.value.trim() || activeWebsite || "";
  const contractAddress = contractAddressInput.value.trim();
  const validationError = validateSubmission(submittedUrl, contractAddress);
  if (validationError) {
    setFormMessage(validationError.message, "error");
    validationError.field.focus();
    return;
  }

  requestInProgress = true;
  const sequence = ++requestSequence;
  results.hidden = true;
  setFormMessage("Running independent website and provider checks…", "loading");
  submitButton.disabled = true;
  submitButton.setAttribute("aria-busy", "true");

  const requestBody = { url: submittedUrl };
  if (contractAddress !== "") {
    requestBody.contractAddress = contractAddress;
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody),
      credentials: "omit",
      cache: "no-store",
      redirect: "error"
    });
    let data;
    try {
      data = await response.json();

    } catch {

      throw new Error("The investigation service returned an unreadable response.");
    }
    if (!response.ok) {
      const message = typeof data.error === "string" ? data.error : "The investigation could not be completed.";

      throw new Error(message);
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {

      throw new Error("The investigation service returned an incomplete report.");
    }
    if (
      !Array.isArray(data.evidence) ||
      !data.threatAssessment ||
      !Array.isArray(data.urlSignals?.findings) ||
      (data.verdict && (
        typeof data.verdict.status !== "string" ||
        typeof data.verdict.summary !== "string" ||
        !Array.isArray(data.verdict.reasons) ||
        !Array.isArray(data.verdict.evidenceReferences)
      ))
    ) {
      throw new Error("The investigation service returned an incomplete report.");
    }
    if (sequence !== requestSequence) {
      return;
    }
    renderResults(data, submittedUrl);
    setFormMessage("Investigation complete. Review each result and its limitations.", "success");
  } catch (error) {

    if (sequence === requestSequence) {
      results.hidden = true;
      setFormMessage(
        error instanceof TypeError
          ? ""
          : error.message || "The investigation could not be completed.",
        "error"
      );
    }
  } finally {
    if (sequence === requestSequence) {
      requestInProgress = false;
      submitButton.disabled = false;
      submitButton.removeAttribute("aria-busy");
    }
  }
}

backButton.addEventListener("click", () => showStep(currentStep - 1));
nextButton.addEventListener("click", () => showStep(currentStep + 1));
openWorkspaceButton.addEventListener("click", openWorkspace);
skipButton.addEventListener("click", openWorkspace);
investigationForm.addEventListener("submit", investigate);
newInvestigationButton.addEventListener("click", () => {
  results.hidden = true;
  currentRecord = null;
  setFormMessage("Enter another URL to start a new investigation.");
  urlInput.focus();
});

document.getElementById("export-json").addEventListener("click", () => {
  if (currentRecord) window.ChainShieldReport.downloadJson(currentRecord);
});
document.getElementById("print-report").addEventListener("click", () => {
  if (currentRecord && !window.ChainShieldReport.printReport(currentRecord)) {
    setFormMessage("Allow pop-ups to open the print-friendly report.", "error");
  }
});
document.getElementById("run-demo").addEventListener("click", () => {
  const id = document.getElementById("demo-scenario").value;
  const scenario = window.ChainShieldDemo.createScenario(id);
  if (!scenario) { setFormMessage("Choose a demo scenario first.", "error"); return; }
  urlInput.value = scenario.url;
  contractAddressInput.value = scenario.ethereumAssessment.address || "";
  resultsWeb3.hidden = true;
  renderResults(scenario, scenario.url, { demo: true });
  setFormMessage("DEMO / SIMULATED scenario loaded. No providers were contacted.", "success");
});
document.getElementById("clear-history").addEventListener("click", () => {
  window.ChainShieldHistory.clear(); renderHistory();
  document.getElementById("history-status").textContent = "Local scan history cleared.";
});
document.getElementById("compare-history").addEventListener("click", () => {
  const ids = Array.from(document.querySelectorAll(".history-select:checked")).map((input) => input.value);
  const records = window.ChainShieldHistory.read();
  if (ids.length !== 2) { document.getElementById("history-status").textContent = "Select exactly two saved investigations to compare."; return; }
  const changes = window.ChainShieldHistory.compare(...ids.map((id) => records.find((record) => record.id === id)));
  document.getElementById("history-status").textContent = changes.length
    ? changes.map((change) => `${change.field}: ${change.before} → ${change.after}`).join(" · ")
    : "No changes in verdict, provider status, evidence, URL indicators, or domain similarity.";
});

document.querySelectorAll(".brand[href='#']").forEach((brandLink) => {
  brandLink.addEventListener("click", (event) => event.preventDefault());
});

if (activeWebsite) {
  urlInput.value = activeWebsite;
  sessionStorage.setItem(INVESTIGATION_TARGET_KEY, activeWebsite);
} else {
  const rememberedTarget = safeHttpUrl(sessionStorage.getItem(INVESTIGATION_TARGET_KEY));
  if (rememberedTarget) {
    urlInput.value = rememberedTarget;
  }
}

renderHistory();

if (localStorage.getItem(ONBOARDING_KEY) === "true") {
  onboardingView.hidden = true;
  workspaceView.hidden = false;
} else {
  showStep(currentStep);
}

if (activeWebsite) {
  setFormMessage(`Ready to investigate the website open in your browser: ${new URL(activeWebsite).hostname}.`);
} else if (urlInput.value) {
  setFormMessage(`Ready to investigate: ${new URL(urlInput.value).hostname}. You can also paste a different URL.`);
} else {
  setFormMessage("No active website URL was provided. Enter or paste an HTTP or HTTPS URL to investigate.");
}
