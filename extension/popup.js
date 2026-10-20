// ============================================================
// ChainShield — Onboarding & Investigation Workspace
// Preserves all existing backend integrations:
//   - TinyFish web intelligence
//   - Google Safe Browsing
//   - URL structure analysis
//   - Ethereum JSON-RPC checks
//   - Etherscan verified-source and proxy-chain analysis
// ============================================================

/* ---- Global state ---- */
let currentStep = 1;
const totalSteps = 4;
let workspaceOpened = false; // prevent duplicate open

/* ---- DOM elements (onboarding) ---- */
const onboardingContainer = document.getElementById('onboarding-container');
const onboardingSteps = document.getElementById('onboarding-steps');
const steps = document.querySelectorAll('.onboarding-step');
const progressSteps = document.querySelectorAll('.progress-step');
const brandHeader = document.getElementById('brand-header');
const skipOnboardingBtn = document.getElementById('skip-onboarding');
const investigateCTA = document.querySelector('.investigation-cta .btn-primary');
const investigationWorkspace = document.getElementById('investigation-workspace');
const workspaceShell = document.getElementById('workspace-shell');
const workspaceResults = document.getElementById('workspace-results');
const investigationForm = document.getElementById('investigation-form');
const urlInput = document.getElementById('url-input');
const contractInput = document.getElementById('contract-input');

/* ---- DOM elements (investigation) ---- */
const resultsWebsite = document.getElementById('results-website');
const resultsWebsiteStatus = document.getElementById('results-website-status');
const resultsWebsiteEvidence = document.getElementById('results-website-evidence');
const resultsSB = document.getElementById('results-sb');
const resultsSBStatus = document.getElementById('results-sb-status');
const resultsSBEvidence = document.getElementById('results-sb-evidence');
const resultsURL = document.getElementById('results-url');
const resultsURLStatus = document.getElementById('results-url-status');
const resultsULEvidence = document.getElementById('results-url-evidence');
const resultsEthereum = document.getElementById('results-ethereum');
const resultsEthereumStatus = document.getElementById('results-ethereum-status');
const resultsContract = document.getElementById('results-contract');
const resultsContractStatus = document.getElementById('results-contract-status');
const resultsContractEvidence = document.getElementById('results-contract-evidence');
const resultsSummary = document.getElementById('results-summary');
const workspaceHeading = document.querySelector('.workspace-heading');
const workspaceSubtitle = document.querySelector('.workspace-subtitle');

/* ---- Step navigation ---- */
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

  // Update step number text
  const stepNumberElements = document.querySelectorAll('.step-number');
  stepNumberElements.forEach(el => {
    el.textContent = stepNumber;
  });

  // Update heading aria-label
  const stepHeading = document.querySelector('.step-heading');
  if (stepHeading) {
    stepHeading.setAttribute('aria-label', `Step ${stepNumber} of ${totalSteps}`);
  }

  // Update navigation button visibility
  const backBtns = document.querySelectorAll('.step-nav-button[data-step="1"]');
  const nextBtns = document.querySelectorAll('.step-nav-button[data-step="2"]');
  const reviewBtns = document.querySelectorAll('.step4-action-btn.secondary');
  const openBtns = document.querySelectorAll('.step4-action-btn[data-onboarding-complete="true"]');

  // Back buttons: hide on step 1, show otherwise
  backBtns.forEach(btn => {
    btn.style.display = stepNumber === 1 ? 'none' : 'inline-block';
    btn.disabled = stepNumber <= 1;
  });

  // Next/Review buttons
  nextBtns.forEach(btn => {
    btn.style.display = stepNumber < totalSteps ? 'inline-block' : 'none';
    btn.disabled = stepNumber >= totalSteps;
  });

  reviewBtns.forEach(btn => {
    btn.style.display = stepNumber === totalSteps ? 'inline-block' : 'none';
  });

  openBtns.forEach(btn => {
    btn.style.display = stepNumber === totalSteps ? 'inline-block' : 'none';
  });
}

/* ---- Onboarding event delegation ---- */
onboardingSteps.addEventListener('click', (event) => {
  const button = event.target.closest('button.step-nav-button');
  if (!button) return;

  const step = parseInt(button.dataset.step, 10);
  if (step >= 1 && step < totalSteps) {
    showStep(step);
  }
});

/* ---- Step 4: Open investigation workspace ---- */
const openStep4Btns = onboardingSteps.querySelectorAll('.step4-action-btn[data-onboarding-complete="true"]');
openStep4Btns.forEach(btn => {
  btn.addEventListener('click', () => {
    // Hide onboarding, show workspace
    onboardingContainer.classList.add('onboarding-hidden');
    investigationWorkspace.hidden = false;
    investigationWorkspace.setAttribute('aria-hidden', 'false');
    workspaceOpened = true;

    // Focus the URL input
    if (urlInput) {
      urlInput.focus();
    }
  });
});

/* ---- "Skip onboarding" ---- */
if (skipOnboardingBtn) {
  skipOnboardingBtn.addEventListener('click', () => {
    onboardingContainer.classList.add('onboarding-hidden');
    investigationWorkspace.hidden = false;
    investigationWorkspace.setAttribute('aria-hidden', 'false');
    workspaceOpened = true;
    if (urlInput) {
      urlInput.focus();
    }
  });
}

/* ---- Keyboard navigation (ArrowLeft/ArrowRight) ---- */
document.addEventListener('keydown', (event) => {
  // Only navigate when onboarding is visible and not in a form
  const isFormElement =
    event.target && (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA');

  if (!isFormElement && onboardingContainer && !onboardingContainer.classList.contains('onboarding-hidden') && currentStep) {
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

/* ---- Investigation form submission ---- */
if (investigationForm) {
  investigationForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const url = urlInput.value.trim();
    const contractAddress = contractInput.value.trim();

    // Basic validation already present in the original handler
    if (!url || url === '') {
      setMessage('A website URL is required.', 'error');
      return;
    }

    // Validate URL protocol
    let supported = false;
    try {
      const parsed = new URL(url);
      supported = parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      // fall through
    }
    if (!supported) {
      setMessage('Only HTTP and HTTPS URLs are supported.', 'error');
      return;
    }

    // Show loading state
    const submitBtn = investigationForm.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn ? submitBtn.textContent : 'Investigate website';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Investigating…';
    }

    setMessage(`Searching the web for public sources about ${new URL(url).hostname}…`, 'loading');

    try {
      const response = await fetch('http://localhost:3000/api/investigations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, contractAddress })
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();

      // Validate response shape (preserve existing checks)
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('The server returned an invalid response.');
      }
      if (
        !['research_available', 'no_results'].includes(data.status) ||
        typeof data.summary !== 'string' ||
        !Array.isArray(data.evidence) ||
        typeof data.domain !== 'string'
      ) {
        throw new Error('The server response was missing expected investigation details.');
      }

      // Hide workspace form, show results
      investigationForm.hidden = true;
      workspaceResults.hidden = false;
      workspaceResults.setAttribute('aria-hidden', 'false');

      // Render results using existing display functions
      renderResults(data);
    } catch (error) {
      console.error('Investigation error:', error);
      setMessage(error instanceof Error ? error.message : 'Something went wrong while contacting the server.', 'error');

      // Re-enable button
      const submitBtn = investigationForm.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Investigate website';
      }
    }
  });
}

/* ---- Render results using existing display logic ---- */
function renderResults(data) {
  // Website intelligence
  renderWebsiteResults(data);

  // Google Safe Browsing
  renderSBResults(data.threatAssessment);

  // URL structure analysis
  renderURLResults(data.urlSignals);

  // Ethereum RPC assessment
  renderEthereumResults(data.ethereumAssessment);

  // Etherscan / contract analysis
  renderContractResults(data.contractAnalysis);

  // Summary
  renderSummary(data);
}

/* ---- Website intelligence results ---- */
function renderWebsiteResults(data) {
  resultsWebsite.hidden = false;
  resultsWebsiteStatus.hidden = false;

  const domainSpecificCount = data.evidence.filter(
    (entry) => entry.category === 'domain_specific'
  ).length;

  if (data.status === 'no_results') {
    resultsWebsiteStatus.textContent = 'Web search found no sources — this is not a safety verdict.';
    resultsWebsiteEvidence.innerHTML = '<li>No public sources were returned for this website.</li>';
  } else {
    resultsWebsiteStatus.textContent = 'Web search sources — not a verified security finding.';
    const domainSpecificEntries = data.evidence.filter(
      (entry) => entry.category === 'domain_specific'
    );

    if (domainSpecificEntries.length > 0) {
      resultsWebsiteEvidence.innerHTML = domainSpecificEntries
        .map(
          (entry) => `<li>
            <strong>${typeof entry.title === 'string' && entry.title.trim() ? entry.title.trim() : ''}</strong>
            ${entry.url ? `<a href="${entry.url}" target="_blank" rel="noopener noreferrer"> ${entry.url}</a>` : ''}
            ${typeof entry.snippet === 'string' && entry.snippet.trim()
              ? `<p class="evidence-snippet">${entry.snippet.trim()}</p>`
              : ''}
          </li>`
        )
        .join('');
    } else {
      resultsWebsiteEvidence.innerHTML = '<li>No domain-specific sources were found.</li>';
    }
  }
}

/* ---- Google Safe Browsing results ---- */
function renderSBResults(assessment) {
  resultsSB.hidden = false;
  resultsSBStatus.hidden = false;

  if (!assessment || typeof assessment !== 'object') {
    resultsSBStatus.textContent = 'Threat assessment unavailable.';
    resultsSBEvidence.innerHTML = '<li>Threat assessment unavailable: the server response omitted this result.</li>';
    return;
  }

  const providers = assessment.providers || [];
  const statusMessages = {
    reported: 'Google Safe Browsing reports a possible threat for the submitted URL.',
    no_match: 'Google Safe Browsing returned no match for the submitted URL. This does not mean the website is safe.',
    incomplete: 'The threat check is incomplete; not all requested checks produced a result.',
    unavailable: 'Google Safe Browsing could not complete this lookup.'
  };

  if (providers.length > 0) {
    const provider = providers[0];
    const matches = provider.matches || [];

    if (matches.length > 0) {
      resultsSBStatus.textContent = statusMessages.reported;
      const matchList = matches
        .slice(0, 3) // show max 3
        .map(
          (match, i) =>
            `<li class="threat-match" key=${i}>Reported indicator: ${formatThreatType(
              match.threatType
            )}</li>`
        )
        .join('');
      resultsSBEvidence.innerHTML = `<ul>${matchList}</ul>`;
    } else {
      resultsSBStatus.textContent = statusMessages.no_match;
      resultsSBEvidence.innerHTML = '<li>No match found for the submitted URL.</li>';
    }
  } else {
    resultsSBStatus.textContent = statusMessages.unavailable;
    resultsSBEvidence.innerHTML = '<li>Threat check unavailable.</li>';
  }
}

/* ---- URL structure analysis results ---- */
function renderURLResults(findings) {
  resultsURL.hidden = false;
  resultsURLStatus.hidden = false;

  if (!findings || findings.length === 0) {
    resultsURLStatus.textContent = 'No structural URL signals were found.';
    resultsULEvidence.innerHTML = '<li>No structural URL signals were found.</li>';
    return;
  }

  resultsURLStatus.textContent = 'URL structure signals found.';

  const list = findings
    .map(
      (finding) => {
        const ruleName =
          typeof finding.ruleId === 'string'
            ? finding.ruleId.replace(/_/g, ' ')
            : 'URL signal';
        const severity =
          typeof finding.severity === 'string' ? finding.severity : 'review';

        return `<li class="url-signal-item">
          <p class="url-signal-heading"><strong>${ruleName} (${severity})</strong></p>
          ${typeof finding.explanation === 'string' && finding.explanation.trim()
            ? `<p class="url-signal-explanation">${finding.explanation.trim()}</p>`
            : ''}
          ${finding.observedFeature &&
          typeof finding.observedFeature === 'object' &&
          typeof finding.observedFeature.value === 'string'
            ? `<p class="url-signal-observed">${finding.observedFeature.label}: ${finding.observedFeature.value}</p>`
            : ''}
        </li>`;
      }
    )
    .join('');

  resultsULEvidence.innerHTML = `<ul>${list}</ul>`;
}

/* ---- Ethereum RPC assessment results ---- */
function renderEthereumResults(assessment) {
  resultsEthereum.hidden = false;

  if (!assessment || assessment.status === 'not_requested') {
    resultsEthereumStatus.textContent = 'Not requested — no contract address supplied.';
    return;
  }

  if (assessment.status === 'unavailable') {
    resultsEthereumStatus.textContent = 'Ethereum RPC could not complete this read-only check.';
    return;
  }

  if (assessment.status === 'available') {
    const fields = [
      ['Address', assessment.address],
      ['Chain ID', assessment.chainId],
      ['Latest block', assessment.latestBlock],
      [
        'Code at latest block',
        assessment.codeStatus === 'bytecode_present'
          ? 'Bytecode present'
          : assessment.codeStatus === 'no_bytecode'
            ? 'No bytecode returned'
            : 'Unavailable'
      ]
    ];

    resultsEthereumStatus.textContent = 'Ethereum RPC assessment';
    resultsEthereumStatus.innerHTML = fields
      .map(([label, value]) => `<p><strong>${label}:</strong> ${value}</p>`)
      .join('');
    return;
  }

  resultsEthereumStatus.textContent = 'Ethereum RPC assessment unavailable.';
}

/* ---- Contract analysis results ---- */
function renderContractResults(analysis) {
  resultsContract.hidden = false;
  resultsContractStatus.hidden = false;

  if (!analysis) {
    resultsContractStatus.textContent = 'No contract analysis performed.';
    resultsContractEvidence.innerHTML = '<li>No contract analysis performed.</li>';
    return;
  }

  const statusMessages = {
    available: 'Verified source was retrieved and analyzed.',
    unverified: 'Etherscan does not provide verified source for this address.',
    unsupported_chain: 'Source analysis currently supports Ethereum Mainnet only.',
    unavailable: 'Verified source analysis could not be completed.',
    incomplete: 'Only part of the contract source or proxy analysis was available.'
  };

  resultsContractStatus.textContent = statusMessages[analysis.status] || statusMessages.unavailable;

  if (analysis.status === 'available' || analysis.status === 'incomplete') {
    // Render key details
    const detailItems = [];
    detailItems.push(`<p><strong>Chain ID:</strong> ${analysis.chainId}</p>`);
    detailItems.push(`<p><strong>Network:</strong> ${analysis.network}</p>`);
    detailItems.push(`<p><strong>Source verified:</strong> ${analysis.sourceVerified !== undefined ? analysis.sourceVerified ? 'Yes' : 'No' : 'Not retrieved'}</p>`);
    detailItems.push(`<p><strong>Contract:</strong> ${analysis.contractName || 'Unnamed'}</p>`);

    if (analysis.reason) {
      detailItems.push(`<p><strong>Limitation:</strong> ${analysis.reason}</p>`);
    }

    // Render layers
    if (Array.isArray(analysis.layers) && analysis.layers.length > 0) {
      detailItems.push('<h5>Layers</h5><ul>');
      analysis.layers.forEach((layer, i) => {
        detailItems.push(
          `<li><strong>Layer ${i + 1}:</strong> ${layer.address ||
            'unknown'} — ${layer.status ||
            'unknown'} — ${layer.proxyStatus || 'unknown'}</li>`
        );
        if (layer.reason) {
          detailItems.push(`<span class="muted">${layer.reason}</span>`);
        }
      });
      detailItems.push('</ul>');
    }

    resultsContractEvidence.innerHTML = detailItems.join('');
  } else {
    resultsContractEvidence.innerHTML = '<li>Contract analysis not available.</li>';
  }
}

/* ---- Summary results ---- */
function renderSummary(data) {
  if (resultsSummary) {
    resultsSummary.hidden = false;
    const domainSpecificCount = data.evidence.filter(
      (entry) => entry.category === 'domain_specific'
    ).length;
    const hasEvidence = data.evidence.length > 0;

    if (data.status === 'no_results') {
      resultsSummary.textContent = 'Web search found no sources — this is not a safety verdict.';
    } else if (hasEvidence && domainSpecificCount > 0) {
      resultsSummary.textContent = `${domainSpecificCount} source${
        domainSpecificCount === 1 ? '' : 's'
      } related to ${data.domain}. Relevance is not proof of malicious activity.`;
    } else {
      resultsSummary.textContent = data.summary || 'Investigation complete.';
    }
  }
}

/* ---- Helper: format threat type ---- */
function formatThreatType(value) {
  if (value === 'SOCIAL_ENGINEERING') {
    return 'potential phishing or social engineering';
  }
  if (value === 'MALWARE') {
    return 'malware';
  }
  return 'potential threat';
}

/* ---- Initialize on DOM content ---- */
document.addEventListener('DOMContentLoaded', () => {
  // Show step 1
  showStep(1);

  // Keyboard focus management for the brand header CTA
  if (skipOnboardingBtn) {
    skipOnboardingBtn.addEventListener('click', () => {
      onboardingContainer.classList.add('onboarding-hidden');
      investigationWorkspace.hidden = false;
      investigationWorkspace.setAttribute('aria-hidden', 'false');
      workspaceOpened = true;
      if (urlInput) {
        urlInput.focus();
      }
    });
  }

  // Ensure first form element gets focus if navigating via keyboard
  const firstFocusable = document.querySelector('input, button');
  if (firstFocusable) {
    // Don't auto-focus on load; let the user decide
  }
});
</script>