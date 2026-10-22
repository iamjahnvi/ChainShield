const API_URL = "http://localhost:3000/api/investigations";
const ONBOARDING_KEY = "chainShieldOnboardingComplete";
const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;

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
const contractInput = document.getElementById("contract-input");
const submitButton = document.getElementById("investigate-button");
const formMessage = document.getElementById("form-message");
const results = document.getElementById("results");
const newInvestigationButton = document.getElementById("new-investigation");
const investigationContext = document.getElementById("investigation-context");

let currentStep = 1;
let requestInProgress = false;
let requestSequence = 0;

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
  const panel = document.getElementById("results-website");
  const evidenceContainer = document.getElementById("results-website-evidence");
  panel.hidden = false;
  clear(evidenceContainer);
  setResultStatus("results-website-status", data.summary || "Website search completed.");

  if (!Array.isArray(data.evidence) || data.evidence.length === 0) {
    evidenceContainer.append(
      element(
        "p",
        "result-content",
        "No public search evidence was returned. This does not establish that the website is safe."
      )
    );
    return;
  }

  data.evidence.forEach((entry) => {
    const item = element("article", "evidence-item");
    item.append(element("div", "evidence-title", entry.title || "Untitled source"));
    const linkUrl = safeHttpUrl(entry.url);
    if (linkUrl) {
      const link = element("a", "evidence-link", linkUrl);
      link.href = linkUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      item.append(link);
    } else if (entry.url) {
      item.append(element("p", "evidence-meta", entry.url));
    }
    if (entry.snippet) {
      item.append(element("p", "evidence-snippet", entry.snippet));
    }
    const categoryLabels = {
      domain_specific: "Domain-specific",
      general_information: "General information",
      irrelevant_or_unclear: "Irrelevant or unclear"
    };
    const metadata = [];
    if (entry.category) {
      metadata.push(categoryLabels[entry.category] || entry.category);
    }
    if (entry.source) {
      metadata.push(`Source: ${entry.source}`);
    }
    if (Number.isInteger(entry.position)) {
      metadata.push(`Position: ${entry.position}`);
    }
    if (entry.siteName) {
      metadata.push(`Site: ${entry.siteName}`);
    }
    if (metadata.length > 0) {
      item.append(element("p", "evidence-meta", metadata.join(" · ")));
    }
    if (entry.categoryReason) {
      item.append(element("p", "evidence-reason", entry.categoryReason));
    }
    evidenceContainer.append(item);
  });
}

function renderSafeBrowsing(assessment) {
  const panel = document.getElementById("results-sb");
  const content = document.getElementById("results-sb-evidence");
  panel.hidden = false;
  clear(content);
  const status = assessment && assessment.status;

  if (!assessment || status === "unavailable") {
    setResultStatus("results-sb-status", "Threat reputation check is unavailable.", "warning");
  } else if (status === "reported") {
    setResultStatus("results-sb-status", "Google Safe Browsing reported a match for the submitted URL.", "warning");
  } else if (status === "no_match") {
    setResultStatus("results-sb-status", "No match was returned for the submitted URL. This is not a guarantee of safety.");
  } else {
    setResultStatus("results-sb-status", `Threat reputation status: ${status || "unknown"}.`);
  }

  const providers = Array.isArray(assessment?.providers) ? assessment.providers : [];
  providers.forEach((provider) => {
    const matches = Array.isArray(provider.matches) ? provider.matches : [];
    matches.forEach((match) => {
      const parts = [
        match.threatType && `Threat type: ${match.threatType}`,
        match.platformType && `Platform: ${match.platformType}`,
        match.threatEntryType && `Entry type: ${match.threatEntryType}`
      ].filter(Boolean);
      content.append(element("p", "evidence-snippet", parts.join(" · ") || "A threat match was reported."));
    });
    if (provider.reason) {
      content.append(element("p", "evidence-meta", `Unavailable reason: ${provider.reason}`));
    }
  });
  if (status === "unavailable" && content.childElementCount === 0) {
    content.append(element("p", "result-content", "No additional provider details were available."));
  }
}

function renderUrlSignals(urlSignals) {
  const panel = document.getElementById("results-url");
  const content = document.getElementById("results-url-evidence");
  panel.hidden = false;
  clear(content);
  const findings = Array.isArray(urlSignals?.findings) ? urlSignals.findings : [];

  if (findings.length === 0) {
    setResultStatus("results-url-status", "No configured URL-structure indicators were found.");
    content.append(element("p", "result-content", "The local checks cover selected patterns only and do not establish that a URL is safe."));
    return;
  }

  setResultStatus("results-url-status", `${findings.length} URL-structure signal${findings.length === 1 ? "" : "s"} returned.`, "warning");
  findings.forEach((finding) => {
    const item = element("article", "signal-item");
    item.append(element("div", "signal-title", finding.title || finding.ruleId || "URL signal"));
    if (finding.severity) {
      item.append(element("span", "signal-observed", `Severity: ${finding.severity}`));
    }
    if (finding.description) {
      item.append(element("p", "evidence-snippet", finding.description));
    }
    if (finding.evidence) {
      item.append(element("p", "signal-observed", finding.evidence));
    }
    content.append(item);
  });
}

function renderEthereumAssessment(assessment) {
  const panel = document.getElementById("results-ethereum");
  const content = document.getElementById("results-ethereum-evidence");
  if (!assessment || assessment.status === "not_requested") {
    panel.hidden = true;
    return;
  }

  panel.hidden = false;
  clear(content);
  const tone = assessment.status === "available" ? "" : "warning";
  setResultStatus(
    "results-ethereum-status",
    assessment.status === "available"
      ? "Read-only Ethereum RPC observations are available."
      : `Ethereum RPC assessment is ${assessment.status || "unavailable"}${assessment.reason ? ` (${assessment.reason})` : ""}.`,
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
  const content = document.getElementById("results-contract-evidence");
  if (!analysis) {
    panel.hidden = true;
    return;
  }

  panel.hidden = false;
  clear(content);
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

function renderResults(data, submittedUrl, contractAddress) {
  clear(investigationContext);
  const context = element("span");
  context.append(element("strong", "", "Website: "), document.createTextNode(submittedUrl));
  if (contractAddress) {
    context.append(document.createElement("br"), element("strong", "", "Contract: "), document.createTextNode(contractAddress));
  }
  investigationContext.append(context);
  renderWebsiteResults(data);
  renderSafeBrowsing(data.threatAssessment);
  renderUrlSignals(data.urlSignals);
  renderEthereumAssessment(data.ethereumAssessment);
  renderContractAnalysis(data.contractAnalysis);
  results.hidden = false;
}

function validateSubmission(submittedUrl, contractAddress) {
  let parsedUrl;
  try {
    parsedUrl = new URL(submittedUrl);
  } catch {
    return { message: "Open the website you want to investigate, then reopen ChainShield from that tab.", field: null };
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return { message: "Only HTTP and HTTPS website URLs are supported.", field: urlInput };
  }
  if (contractAddress && !ADDRESS_PATTERN.test(contractAddress)) {
    return {
      message: "Enter a contract address beginning with 0x and containing exactly 40 hexadecimal characters.",
      field: contractInput
    };
  }
  return null;
}

async function investigate(event) {
  event.preventDefault();
  if (requestInProgress) {
    return;
  }

  const submittedUrl = urlInput.value.trim();
  const contractAddress = contractInput.value.trim();
  const validationError = validateSubmission(submittedUrl, contractAddress);
  if (validationError) {
    setFormMessage(validationError.message, "error");
    validationError.field?.focus();
    return;
  }

  requestInProgress = true;
  const sequence = ++requestSequence;
  results.hidden = true;
  setFormMessage("Running independent website and provider checks…", "loading");
  submitButton.disabled = true;
  submitButton.setAttribute("aria-busy", "true");

  const requestBody = { url: submittedUrl };
  if (contractAddress) {
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
    if (sequence !== requestSequence) {
      return;
    }
    renderResults(data, submittedUrl, contractAddress);
    setFormMessage("Investigation complete. Review each result and its limitations.", "success");
  } catch (error) {
    if (sequence === requestSequence) {
      results.hidden = true;
      setFormMessage(
        error instanceof TypeError
          ? "Could not connect to the local ChainShield backend. Make sure the server is running on port 3000."
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
  setFormMessage("Enter another URL to start a new investigation.");
  urlInput.focus();
});

document.querySelectorAll(".brand[href='#']").forEach((brandLink) => {
  brandLink.addEventListener("click", (event) => event.preventDefault());
});

if (localStorage.getItem(ONBOARDING_KEY) === "true") {
  onboardingView.hidden = true;
  workspaceView.hidden = false;
} else {
  showStep(currentStep);
}

const activeWebsite = safeHttpUrl(new URLSearchParams(location.search).get("target"));
if (activeWebsite) {
  urlInput.value = activeWebsite;
  setFormMessage(`Ready to investigate the website open in your browser: ${new URL(activeWebsite).hostname}.`);
}
