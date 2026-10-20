const API_URL = "http://localhost:3000/api/investigations";
const VALID_STATUSES = ["research_available", "no_results"];

const GROUP_DEFINITIONS = [
  {
    category: "domain_specific",
    title: "Domain-specific sources",
    note: "Sources hosted on this hostname or specifically about it. Relevance to the domain does not establish malicious activity."
  },
  {
    category: "general_information",
    title: "General security resources",
    note: "Background security information that does not reference this hostname. Not evidence about this domain."
  },
  {
    category: "irrelevant_or_unclear",
    title: "Weak or unclear matches",
    note: "Results that could not be clearly connected to this hostname."
  }
];

// --- Onboarding state ---
let currentStep = 1;
const totalSteps = 4;

// DOM elements
const onboarding = document.getElementById('onboarding');
const steps = document.querySelectorAll('.onboarding-step');
const progressSteps = document.querySelectorAll('.progress-step');
const investigateCTA = document.getElementById('investigate-cta');
const investigateButton = document.getElementById('investigate-button');

// Show a specific step by number
function showStep(stepNumber) {
  if (stepNumber < 1 || stepNumber > totalSteps) return;

  currentStep = stepNumber;

  // Hide all steps
  steps.forEach(step => {
    step.classList.remove('active');
    step.setAttribute('aria-hidden', 'true');
  });

  // Show the target step
  const targetStep = document.getElementById(`step-${stepNumber}`);
  if (targetStep) {
    targetStep.classList.add('active');
    targetStep.removeAttribute('aria-hidden');
  }

  // Update progress indicator
  progressSteps.forEach((step, index) => {
    if (index + 1 === stepNumber) {
      step.classList.add('active');
      step.classList.remove('done');
    } else if (index < stepNumber - 1) {
      step.classList.add('done');
      step.classList.remove('active');
    } else {
      step.classList.remove('done');
      step.classList.remove('active');
    }
  });

  // Update navigation button states
  // Step 1: Back disabled, show Next
  // Step 4: Show "Review" and "Open ChainShield", hide Next
  const backBtn = document.querySelector('.step-nav-button[data-step="1"]');
  const nextBtn = document.querySelector('.step-nav-button[data-step="2"]');
  const reviewBtn = document.querySelector('.step4-action-btn.secondary');
  const openBtn = document.querySelector('.step4-action-btn[data-onboarding-complete="true"]');

  if (backBtn) {
    backBtn.disabled = stepNumber <= 1;
    backBtn.style.display = stepNumber === 1 ? 'none' : 'inline-block';
  }
  if (nextBtn) {
    nextBtn.disabled = stepNumber >= totalSteps;
    nextBtn.style.display = stepNumber < totalSteps ? 'inline-block' : 'none';
  }
  if (reviewBtn) {
    reviewBtn.style.display = stepNumber === totalSteps ? 'inline-block' : 'none';
  }
  if (openBtn) {
    openBtn.style.display = stepNumber === totalSteps ? 'inline-block' : 'none';
  }

  // Update step heading aria-label
  const stepHeading = document.querySelector('.step-heading');
  if (stepHeading) {
    stepHeading.setAttribute('aria-label', `Step ${stepNumber} of ${totalSteps}`);
  }
}

// Initialize onboarding on DOM content loaded
document.addEventListener('DOMContentLoaded', () => {
  // Show step 1
  showStep(1);

  // Step navigation: delegate from the onboarding container
  onboarding.addEventListener('click', (event) => {
    const button = event.target.closest('button.step-nav-button');
    if (!button) return;

    const step = parseInt(button.dataset.step, 10);
    if (step >= 1 && step < totalSteps) {
      showStep(step);
    }
  });

  // Step 4: "Review how it works" goes back to step 3
  const reviewButton = onboarding.querySelector('.step4-action-btn.secondary');
  if (reviewButton) {
    reviewButton.addEventListener('click', () => {
      showStep(3);
    });
  }

  // Step 4: "Open ChainShield" completes onboarding and shows investigation CTA
  const openButton = onboarding.querySelector('.step4-action-btn[data-onboarding-complete="true"]');
  if (openButton) {
    openButton.addEventListener('click', () => {
      // Hide onboarding, show investigation CTA
      onboarding.classList.add('onboarding-hidden');
      investigateCTA.hidden = false;
      // Focus the investigate button
      if (investigateButton) {
        investigateButton.focus();
      }
    });
  }

  // Keyboard navigation: ArrowLeft/ArrowRight to navigate steps
  let keyboardStepTimer = null;
  document.addEventListener('keydown', (event) => {
    // Prevent default on non-step pages
    if (!onboarding.classList.contains('onboarding-hidden') && currentStep) {
      if (event.key === 'ArrowRight') {
        event.preventDefault();
        if (currentStep < totalSteps) {
          showStep(currentStep + 1);
        }
      }
      if (event.key === 'ArrowLeft') {
        event.preventDefault();
        if (currentStep > 1) {
          showStep(currentStep - 1);
        }
      }
    }
  });
});

// --- Existing investigation functionality (unchanged) ---

const button = document.querySelector("#investigate-button");
const domainLabel = document.querySelector("#page-domain");
const message = document.querySelector("#message");
const result = document.querySelector("#result");
const resultStatus = document.querySelector("#result-status");
const resultSummary = document.querySelector("#result-summary");
const domainNote = document.querySelector("#domain-note");
const evidenceGroups = document.querySelector("#evidence-groups");
const threatAssessment = document.querySelector("#threat-assessment");
const threatDetails = document.querySelector("#threat-details");
const urlSignals = document.querySelector("#url-signals");
const urlSignalDetails = document.querySelector("#url-signal-details");
const contractAddressInput = document.querySelector("#contract-address");
const ethereumAssessment = document.querySelector("#ethereum-assessment");
const ethereumDetails = document.querySelector("#ethereum-details");
const contractAnalysis = document.querySelector("#contract-analysis");
const contractAnalysisDetails = document.querySelector("#contract-analysis-details");

function setMessage(text, state = "") {
  message.textContent = text;
  if (state) {
    message.dataset.state = state;
  } else {
    delete message.dataset.state;
  }
}

function isSupportedUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function buildEvidenceItem(entry) {
  const item = document.createElement("li");

  const title =
    typeof entry.title === "string" && entry.title.trim() !== ""
      ? entry.title.trim()
      : "";
  const url =
    typeof entry.url === "string" && isSupportedUrl(entry.url) ? entry.url : "";

  if (url) {
    const link = document.createElement("a");
    link.href = url;
    link.textContent = title || url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    item.append(link);
  } else if (title) {
    const label = document.createElement("span");
    label.textContent = title;
    item.append(label);
  }

  if (typeof entry.snippet === "string" && entry.snippet.trim() !== "") {
    const snippet = document.createElement("p");
    snippet.className = "evidence-snippet";
    snippet.textContent = entry.snippet.trim();
    item.append(snippet);
  }

  if (typeof entry.categoryReason === "string" && entry.categoryReason.trim() !== "") {
    const reason = document.createElement("p");
    reason.className = "evidence-reason";
    reason.textContent = entry.categoryReason.trim();
    item.append(reason);
  }

  const metaParts = [];
  if (typeof entry.siteName === "string" && entry.siteName.trim() !== "") {
    metaParts.push(entry.siteName.trim());
  }
  if (typeof entry.position === "number" && Number.isFinite(entry.position)) {
    metaParts.push(`Result #${entry.position}`);
  }
  metaParts.push(
    typeof entry.source === "string" && entry.source.trim() !== ""
      ? entry.source.trim()
      : "Web search"
  );

  const meta = document.createElement("p");
  meta.className = "evidence-meta";
  meta.textContent = metaParts.join(" · ");
  item.append(meta);

  return item;
}

const KNOWN_CATEGORIES = GROUP_DEFINITIONS.map((definition) => definition.category);

function groupEntries(evidence, category) {
  return evidence.filter((entry) => {
    if (!entry || typeof entry !== "object") {
      return false;
    }
    if (typeof entry.category === "string" && KNOWN_CATEGORIES.includes(entry.category)) {
      return entry.category === category;
    }
    return category === "irrelevant_or_unclear";
  });
}

function buildGroup(definition, entries) {
  const group = document.createElement("section");
  group.className = "evidence-group";

  const heading = document.createElement("h3");
  heading.className = "evidence-group-title";
  heading.textContent = `${definition.title} (${entries.length})`;
  group.append(heading);

  const note = document.createElement("p");
  note.className = "evidence-group-note";
  note.textContent = definition.note;
  group.append(note);

  const list = document.createElement("ul");
  list.className = "evidence-list";
  for (const entry of entries) {
    list.append(buildEvidenceItem(entry));
  }
  group.append(list);

  return group;
}

function displayResult(data) {
  const evidence = Array.isArray(data.evidence) ? data.evidence : [];
  const domainSpecificCount = groupEntries(evidence, "domain_specific").length;
  const hasEvidence = evidence.length > 0;

  resultStatus.textContent =
    data.status === "no_results"
      ? "Web search found no sources — this is not a safety verdict."
      : "Web search sources — not a verified security finding.";
  resultSummary.textContent = data.summary;

  if (domainSpecificCount === 0) {
    domainNote.textContent = `No domain-specific evidence about ${data.domain} was found. This does not mean the website is safe.`;
    domainNote.dataset.tone = "empty";
  } else {
    domainNote.textContent =
      `${domainSpecificCount} source${domainSpecificCount === 1 ? "" : "s"} ` +
      `related to ${data.domain}. Relevance is not proof of malicious activity.`;
    delete domainNote.dataset.tone;
  }

  evidenceGroups.replaceChildren();

  if (!hasEvidence) {
    const empty = document.createElement("p");
    empty.className = "evidence-empty";
    empty.textContent = "No public sources were returned for this website.";
    evidenceGroups.append(empty);
  } else {
    for (const definition of GROUP_DEFINITIONS) {
      const entries = groupEntries(evidence, definition.category);
      if (entries.length > 0) {
        evidenceGroups.append(buildGroup(definition, entries));
      }
    }
  }

  displayThreatAssessment(data.threatAssessment);
  displayUrlSignals(data.urlSignals);
  displayEthereumAssessment(data.ethereumAssessment);
  displayContractAnalysis(data.contractAnalysis);
  result.hidden = false;
}

function displayEthereumAssessment(assessment) {
  ethereumDetails.replaceChildren();
  if (!assessment || assessment.status === "not_requested") {
    ethereumAssessment.hidden = true;
    return;
  }

  ethereumAssessment.hidden = false;
  if (assessment.status !== "available") {
    const unavailable = document.createElement("p");
    unavailable.className = "ethereum-status";
    unavailable.textContent =
      "Ethereum RPC could not complete this read-only check. No conclusion was made about the address.";
    ethereumDetails.append(unavailable);
    return;
  }

  const fields = [
    ["Address", assessment.address],
    ["Chain ID", assessment.chainId],
    ["Latest block", assessment.latestBlock],
    [
      "Code at latest block",
      assessment.codeStatus === "bytecode_present"
        ? "Bytecode present"
        : assessment.codeStatus === "no_bytecode"
          ? "No bytecode returned"
          : "Unavailable"
    ]
  ];

  for (const [label, value] of fields) {
    if (typeof value !== "string") {
      continue;
    }
    const row = document.createElement("p");
    row.className = "ethereum-detail";
    row.textContent = `${label}: ${value}`;
    ethereumDetails.append(row);
  }
}

function displayContractAnalysis(analysis) {
  contractAnalysisDetails.replaceChildren();
  if (!analysis || typeof analysis !== "object") {
    contractAnalysis.hidden = true;
    return;
  }

  contractAnalysis.hidden = false;
  const statusMessages = {
    available: "Verified source was retrieved and analyzed.",
    unverified: "Etherscan does not provide verified source for this address.",
    unsupported_chain: "Source analysis currently supports Ethereum Mainnet only.",
    unavailable: "Verified source analysis could not be completed.",
    incomplete: "Only part of the contract source or proxy analysis was available."
  };
  const status = document.createElement("p");
  status.className = "contract-analysis-status";
  status.textContent = statusMessages[analysis.status] || statusMessages.unavailable;
  contractAnalysisDetails.append(status);

  const reasonMessages = {
    config_missing: "Etherscan is not configured on the backend.",
    timeout: "The Etherscan source lookup timed out.",
    rate_limited: "Etherscan rate limit was reached.",
    network: "Etherscan could not be reached.",
    http_rejection: "Etherscan rejected the source lookup.",
    api_error: "Etherscan could not complete the source lookup.",
    response_too_large: "The Etherscan response exceeded the allowed size.",
    bad_response: "Etherscan returned malformed source data.",
    provider_error: "The Etherscan source lookup failed.",
    rpc_chain_unavailable: "The Ethereum network could not be confirmed by RPC.",
    source_unverified: "Source is not verified on Etherscan.",
    source_unavailable: "Etherscan source lookup did not complete.",
    malformed_source_response: "The source response could not be parsed.",
    malformed_proxy_metadata: "Proxy metadata was malformed.",
    missing_implementation_address: "Etherscan did not provide an implementation address.",
    invalid_implementation_address: "The implementation address failed validation and was not queried.",
    cycle_detected: "A repeated address was detected; traversal stopped.",
    hop_limit_exceeded: "The maximum of three implementation hops was reached.",
    capability_analysis_incomplete: "Some source capability indicators could not be classified."
  };

  const addDetail = (label, value) => {
    if (typeof value !== "string" || value.trim() === "") {
      return;
    }
    const detail = document.createElement("p");
    detail.className = "contract-analysis-detail";
    detail.textContent = `${label}: ${value}`;
    contractAnalysisDetails.append(detail);
  };

  addDetail("Chain ID", analysis.chainId);
  addDetail("Network", analysis.network);
  if (typeof analysis.reason === "string") {
    addDetail(
      "Analysis limitation",
      reasonMessages[analysis.reason] || "Part of the analysis could not be completed."
    );
  }
  if (typeof analysis.sourceVerified === "boolean") {
    addDetail("Source verified", analysis.sourceVerified ? "Yes" : "No");
  }
  if (typeof analysis.contractName === "string") {
    addDetail("Contract", analysis.contractName);
  }
  if (typeof analysis.message === "string") {
    addDetail("Details", analysis.message);
  }

  const renderCapabilities = (headingText, capabilities) => {
    if (!Array.isArray(capabilities)) {
      return;
    }
    const heading = document.createElement("h3");
    heading.className = "contract-analysis-subheading";
    heading.textContent = headingText;
    contractAnalysisDetails.append(heading);

    for (const item of capabilities) {
      if (!item || typeof item !== "object") {
        continue;
      }
      const card = document.createElement("div");
      card.className = "contract-capability";
      const title = document.createElement("p");
      title.className = "contract-capability-title";
      const capabilityStatus = ["detected", "not_detected", "unknown"].includes(item.status)
        ? item.status.replace(/_/g, " ")
        : "unknown";
      title.textContent = `${typeof item.name === "string" ? item.name : "Capability"}: ${capabilityStatus}`;
      card.append(title);
      for (const [field, className] of [
        ["explanation", "contract-capability-explanation"],
        ["limitation", "contract-capability-limitation"]
      ]) {
        if (typeof item[field] === "string" && item[field].trim() !== "") {
          const text = document.createElement("p");
          text.className = className;
          text.textContent = item[field].trim();
          card.append(text);
        }
      }
      if (Array.isArray(item.evidence)) {
        for (const entry of item.evidence) {
          if (typeof entry !== "string") {
            continue;
          }
          const evidence = document.createElement("p");
          evidence.className = "contract-capability-evidence";
          evidence.textContent = `Evidence: ${entry}`;
          card.append(evidence);
        }
      }
      contractAnalysisDetails.append(card);
    }
  };

  if (Array.isArray(analysis.layers)) {
    for (const [index, layer] of analysis.layers.entries()) {
      if (!layer || typeof layer !== "object") {
        continue;
      }
      const layerHeading = document.createElement("h3");
      layerHeading.className = "contract-analysis-subheading";
      layerHeading.textContent =
        index === 0 ? "Submitted contract" : `Implementation layer ${index}`;
      contractAnalysisDetails.append(layerHeading);
      addDetail("Contract address", layer.address);
      const proxyLabel = {
        proxy: "Yes",
        not_proxy: "No",
        not_checked: "Not checked",
        unknown: "Unknown"
      }[layer.proxyStatus] || "Unknown";
      addDetail("Proxy", proxyLabel);
      addDetail(
        "Source verified",
        layer.sourceVerified === true
          ? "Yes"
          : layer.sourceVerified === false
            ? "No"
            : "Not retrieved"
      );
      const layerStatusMessages = {
        available: "Analyzed",
        incomplete: "Partially analyzed",
        unverified: "Source not verified",
        unavailable: "Source unavailable",
        malformed: "Malformed source or proxy metadata",
        cycle: "Repeated address; cycle detected",
        hop_limit: "Not analyzed; maximum proxy depth reached"
      };
      addDetail(
        "Layer status",
        layerStatusMessages[layer.status] || "Not analyzed"
      );
      if (typeof layer.reason === "string") {
        addDetail(
          "Layer limitation",
          reasonMessages[layer.reason] || "This layer could not be fully analyzed."
        );
      }
      addDetail("Contract", layer.contractName);
      if (typeof layer.implementationAddress === "string") {
        addDetail("Next implementation address", layer.implementationAddress);
      }
      renderCapabilities(`Layer ${index} capability indicators`, layer.capabilities);
    }
  } else {
    if (analysis.proxy && typeof analysis.proxy === "object") {
      addDetail("Proxy", analysis.proxy.isProxy === true ? "Yes" : "No");
      addDetail("Implementation address", analysis.proxy.implementationAddress);
    }
    if (analysis.proxyAnalysis && typeof analysis.proxyAnalysis === "object") {
      renderCapabilities("Proxy source indicators", analysis.proxyAnalysis.capabilities);
    }
    if (
      analysis.implementationAnalysis &&
      typeof analysis.implementationAnalysis === "object"
    ) {
      addDetail("Implementation source", analysis.implementationAnalysis.status);
      addDetail(
        "Implementation source verified",
        analysis.implementationAnalysis.sourceVerified === true
          ? "Yes"
          : analysis.implementationAnalysis.sourceVerified === false
            ? "No"
            : "Not retrieved"
      );
      addDetail("Implementation contract", analysis.implementationAnalysis.contractName);
      addDetail("Implementation address", analysis.implementationAnalysis.address);
      renderCapabilities(
        "Implementation source indicators",
        analysis.implementationAnalysis.capabilities
      );
    }
  }
}

function displayUrlSignals(assessment) {
  urlSignalDetails.replaceChildren();
  urlSignals.hidden = false;

  const findings =
    assessment && typeof assessment === "object" && Array.isArray(assessment.findings)
      ? assessment.findings.filter(
          (finding) => finding && typeof finding === "object"
        )
      : [];

  if (findings.length === 0) {
    const empty = document.createElement("p");
    empty.className = "url-signal-empty";
    empty.textContent = "No structural URL signals were found.";
    urlSignalDetails.append(empty);
    return;
  }

  for (const finding of findings) {
    const item = document.createElement("div");
    item.className = "url-signal-item";

    const heading = document.createElement("p");
    heading.className = "url-signal-heading";
    const ruleName =
      typeof finding.ruleId === "string" ? finding.ruleId.replace(/_/g, " ") : "URL signal";
    const severity =
      typeof finding.severity === "string" ? finding.severity : "review";
    heading.textContent = `${ruleName} (${severity})`;
    item.append(heading);

    if (typeof finding.explanation === "string" && finding.explanation.trim() !== "") {
      const explanation = document.createElement("p");
      explanation.className = "url-signal-explanation";
      explanation.textContent = finding.explanation.trim();
      item.append(explanation);
    }

    if (
      finding.observedFeature &&
      typeof finding.observedFeature === "object" &&
      typeof finding.observedFeature.value === "string"
    ) {
      const observed = document.createElement("p");
      observed.className = "url-signal-observed";
      const label =
        typeof finding.observedFeature.label === "string"
          ? finding.observedFeature.label
          : "Observed feature";
      observed.textContent = `${label}: ${finding.observedFeature.value}`;
      item.append(observed);
    }

    urlSignalDetails.append(item);
  }
}

function displayThreatAssessment(assessment) {
  threatDetails.replaceChildren();
  threatAssessment.hidden = false;

  if (!assessment || typeof assessment !== "object") {
    threatDetails.append(
      createThreatMessage(
        "Threat assessment unavailable: the server response omitted this result. Restart the current backend and try again.",
        "unavailable"
      )
    );
    return;
  }

  const providers = Array.isArray(assessment.providers) ? assessment.providers : [];
  const statusMessages = {
    reported: "Google Safe Browsing reports a possible threat for the submitted URL.",
    no_match: "Google Safe Browsing returned no match for the submitted URL. This does not mean the website is safe.",
    incomplete: "The threat check is incomplete; not all requested checks produced a result.",
    unavailable: "Google Safe Browsing could not complete this lookup."
  };

  threatDetails.append(
    createThreatMessage(
      statusMessages[assessment.status] || statusMessages.unavailable,
      assessment.status
    )
  );

  for (const provider of providers) {
    if (!provider || typeof provider !== "object") {
      continue;
    }
    const matches = Array.isArray(provider.matches) ? provider.matches : [];
    for (const match of matches) {
      if (!match || typeof match !== "object") {
        continue;
      }
      const item = document.createElement("p");
      item.className = "threat-match";
      item.textContent = `Reported indicator: ${formatThreatType(match.threatType)}`;
      if (typeof match.matchedUrl === "string" && isSupportedUrl(match.matchedUrl)) {
        item.append(document.createTextNode(" — "));
        const link = document.createElement("a");
        link.href = match.matchedUrl;
        link.textContent = match.matchedUrl;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        item.append(link);
      }
      threatDetails.append(item);
    }
  }

  if (assessment.status === "reported") {
    const attribution = document.createElement("p");
    attribution.className = "threat-attribution";
    const link = document.createElement("a");
    link.href = "https://developers.google.com/safe-browsing/v4/advisory";
    link.textContent = "Advisory provided by Google";
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    attribution.append(link);
    threatDetails.append(attribution);
  }
}

function createThreatMessage(text, status) {
  const message = document.createElement("p");
  message.className = "threat-status";
  message.dataset.status = status;
  message.textContent = text;
  return message;
}

function formatThreatType(value) {
  if (value === "SOCIAL_ENGINEERING") {
    return "potential phishing or social engineering";
  }
  if (value === "MALWARE") {
    return "malware";
  }
  return "potential threat";
}

button.addEventListener("click", async () => {
  button.disabled = true;
  result.hidden = true;
  threatAssessment.hidden = true;
  urlSignals.hidden = true;
  ethereumAssessment.hidden = true;
  contractAnalysis.hidden = true;
  domainLabel.textContent = "";
  setMessage("Checking the active tab…");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url || !isSupportedUrl(tab.url)) {
      setMessage("This page cannot be investigated. Open a website with an http:// or https:// address and try again.", "error");
      return;
    }

    const domain = new URL(tab.url).hostname;
    const contractAddress = contractAddressInput.value.trim();
    if (contractAddress !== "" && !/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
      setMessage(
        "Enter an Ethereum address as 0x followed by exactly 40 hexadecimal characters, or leave the field empty.",
        "error"
      );
      return;
    }

    domainLabel.textContent = `Website: ${domain}`;
    setMessage(`Searching the web for public sources about ${domain}…`, "loading");

    let response;
    try {
      const requestBody = { url: tab.url };
      if (contractAddress !== "") {
        requestBody.contractAddress = contractAddress;
      }
      response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody)
      });
    } catch {
      throw new Error("Could not reach the local server. Make sure it is running on port 3000.");
    }

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("The server returned an invalid response. Check that the backend is running correctly.");
    }

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("The server returned an invalid response. Check that the backend is running correctly.");
    }

    if (!response.ok) {
      throw new Error(data.error || `The server returned an error (${response.status}).`);
    }

    if (
      !VALID_STATUSES.includes(data.status) ||
      data.investigationType !== "web_search" ||
      typeof data.summary !== "string" ||
      !Array.isArray(data.evidence) ||
      typeof data.domain !== "string"
    ) {
      throw new Error("The server response was missing expected investigation details.");
    }

    displayResult(data);

    if (data.status === "no_results") {
      setMessage("Search finished, but no public sources were found for this website.");
    } else {
      setMessage("Web search complete. Review the sources below — no security scan was performed.", "success");
    }
  } catch (error) {
    setMessage(error instanceof Error ? error.message : "Something went wrong while contacting the server.", "error");
  } finally {
    button.disabled = false;
  }
});