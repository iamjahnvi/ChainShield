const express = require("express");
const {
  TinyFishError,
  buildInvestigationQuery,
  searchTinyFish
} = require("../tinyfish");
const { CATEGORIES, prepareEvidence } = require("../classification");
const {
  SafeBrowsingError,
  checkSafeBrowsing
} = require("../safe-browsing");
const { analyzeUrl } = require("../url-analysis");
const {
  EthereumRpcError,
  checkEthereumContract,
  validateContractAddress
} = require("../ethereum-rpc");
const {
  analyzeContractSource
} = require("../etherscan");

const router = express.Router();

const NO_RESULTS_SUMMARY =
  "The web search returned no public sources for this website. This does not mean the website is safe.";

function buildSummary(domain, evidence) {
  const domainCount = evidence.filter(
    (entry) => entry.category === CATEGORIES.DOMAIN_SPECIFIC
  ).length;

  if (domainCount === 0) {
    return (
      `No domain-specific sources about ${domain} were found. ` +
      `The search returned ${evidence.length} other source(s) to review. ` +
      "This does not mean the website is safe."
    );
  }

  const domainLabel = `${domainCount} source${domainCount === 1 ? "" : "s"}`;
  return (
    `Web search returned sources for review, including ${domainLabel} ` +
    `related to ${domain}. Relevance is not proof of malicious activity. ` +
    "These results do not establish whether the website is safe or malicious."
  );
}

function buildThreatAssessment(result) {
  if (result.status === "rejected") {
    const error = result.reason;
    const reason =
      error instanceof SafeBrowsingError ? error.code : "provider_error";
    const httpStatus =
      error instanceof SafeBrowsingError && error.httpStatus !== undefined
        ? `, httpStatus=${error.httpStatus}`
        : "";
    const diagnostic = error instanceof SafeBrowsingError ? error.diagnostic : undefined;
    const diagnosticParts = [];
    if (diagnostic && diagnostic.googleCode !== undefined) {
      diagnosticParts.push(`googleCode=${diagnostic.googleCode}`);
    }
    if (diagnostic && diagnostic.googleStatus) {
      diagnosticParts.push(`googleStatus=${diagnostic.googleStatus}`);
    }
    if (diagnostic && diagnostic.reasons) {
      diagnosticParts.push(`reasons=${diagnostic.reasons.join(",")}`);
    }
    if (diagnostic && diagnostic.message) {
      diagnosticParts.push(`googleMessage="${diagnostic.message}"`);
    }
    const diagnosticSuffix =
      diagnosticParts.length > 0 ? `, ${diagnosticParts.join(", ")}` : "";
    console.error(
      `[investigations] Google Safe Browsing check unavailable (category=${reason}${httpStatus}${diagnosticSuffix})`
    );
    return {
      status: "unavailable",
      providers: [
        {
          id: "google_safe_browsing",
          name: "Google Safe Browsing",
          status: "unavailable",
          reason,
          ...(error instanceof SafeBrowsingError && error.httpStatus !== undefined
            ? { httpStatus: error.httpStatus }
            : {})
        }
      ]
    };
  }

  const { httpStatus, matches } = result.value;
  console.info(
    `[investigations] Google Safe Browsing response (httpStatus=${httpStatus}, category=${
      matches.length > 0 ? "match" : "no_match"
    })`
  );
  return {
    status: matches.length > 0 ? "reported" : "no_match",
    providers: [
      {
        id: "google_safe_browsing",
        name: "Google Safe Browsing",
        status: matches.length > 0 ? "reported" : "no_match",
        scope: "submitted_url",
        matches
      }
    ]
  };
}

function buildEthereumAssessment(result, contractAddress) {
  if (!contractAddress) {
    return { status: "not_requested" };
  }

  if (result.status === "rejected") {
    const error = result.reason;
    const reason = error instanceof EthereumRpcError ? error.code : "provider_error";
    console.warn(`[investigations] Ethereum RPC check unavailable (category=${reason})`);
    return {
      status: "unavailable",
      address: contractAddress.toLowerCase(),
      reason
    };
  }

  return {
    status: "available",
    ...result.value
  };
}

const ERROR_RESPONSES = {
  config_missing: {
    status: 503,
    error:
      "The server is missing its search API configuration. Set TINYFISH_API_KEY in server/.env and restart the backend."
  },
  timeout: {
    status: 504,
    error: "The web search timed out. Please try again."
  },
  rate_limited: {
    status: 503,
    error: "The web search service is busy. Please try again shortly."
  },
  upstream: {
    status: 502,
    error: "The web search service is unavailable. Please try again later."
  },
  bad_response: {
    status: 502,
    error: "The web search service returned an unexpected response. Please try again later."
  },
  network: {
    status: 502,
    error: "The web search service is unreachable. Please try again later."
  }
};

router.post("/", async (req, res) => {
  const {
    url: submittedUrl,
    contractAddress
  } = req.body || {};
  if (typeof submittedUrl !== "string" || submittedUrl.trim() === "") {
    return res.status(400).json({ error: "A URL is required." });
  }

  let url;
  try {
    url = new URL(submittedUrl);
  } catch {
    return res.status(400).json({ error: "The URL is malformed." });
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return res.status(400).json({ error: "Only HTTP and HTTPS URLs are supported." });
  }

  if (contractAddress !== undefined && contractAddress !== "" && !validateContractAddress(contractAddress)) {
    return res.status(400).json({
      error: "contractAddress must be a 20-byte hexadecimal address beginning with 0x."
    });
  }

  const domain = url.hostname;
  const urlSignals = { findings: analyzeUrl(url) };

  try {
    const effectiveContractAddress = contractAddress !== undefined && contractAddress !== "" ? contractAddress : undefined;
    const ethereumPromise = effectiveContractAddress
      ? checkEthereumContract(effectiveContractAddress)
      : Promise.resolve(null);

    const [searchResult, threatResult, ethereumResult] = await Promise.allSettled([
      searchTinyFish(buildInvestigationQuery(domain)),
      checkSafeBrowsing(url.toString()),
      ethereumPromise
    ]);

    if (searchResult.status === "rejected") {
      throw searchResult.reason;
    }

    const threatAssessment = buildThreatAssessment(threatResult);
    const ethereumAssessment = effectiveContractAddress
      ? buildEthereumAssessment(ethereumResult, effectiveContractAddress)
      : { status: "not_requested" };
    let contractAnalysis;
    if (effectiveContractAddress) {
      try {
        const chainId = ethereumAssessment.status === "available" ? ethereumAssessment.chainId : undefined;
        const analysisResult = await analyzeContractSource(effectiveContractAddress, chainId);
        contractAnalysis = analysisResult;
      } catch (error) {
        contractAnalysis = { status: "unavailable" };
      }
    }
    const results = searchResult.value;
    const evidence = prepareEvidence(results, domain);

const alternativeSites = {};
if (domain === "zzztd.com") {
  alternativeSites.zzztd = {
    label: "Best alternative website:",
    link: "https://www.binance.com/en-IN",
    text: "Binance"
  };
}

if (evidence.length === 0) {
      return res.json({
        status: "no_results",
        summary: NO_RESULTS_SUMMARY,
        domain,
        evidence: [],
        investigationType: "web_search",
        demo: false,
        threatAssessment,
        urlSignals,
        ethereumAssessment,
        contractAnalysis: effectiveContractAddress ? contractAnalysis : undefined
      });
    }

return res.json({
  status: "research_available",
  summary: buildSummary(domain, evidence),
  domain,
  evidence,
  investigationType: "web_search",
  demo: false,
  threatAssessment,
  urlSignals,
  ethereumAssessment,
  contractAnalysis: effectiveContractAddress ? contractAnalysis : undefined,
  alternativeSites
});
  } catch (error) {
    const isTinyFishError = error instanceof TinyFishError;
    const code = isTinyFishError ? error.code : "unknown";
    const mapped =
      ERROR_RESPONSES[code] || {
        status: 500,
        error: "Something went wrong while running the web search."
      };
    const upstreamStatus =
      isTinyFishError && error.upstreamStatus !== undefined
        ? `, upstreamStatus=${error.upstreamStatus}`
        : "";

    console.error(
      `[investigations] web search failed (code=${code}${upstreamStatus}, errorName=${
        error && error.name ? error.name : "unknown"
      })`
    );

    return res.status(mapped.status).json({ error: mapped.error });
  }
});

module.exports = router;
