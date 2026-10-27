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
const { buildVerdict } = require("../verdict");

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
        httpStatus,
        matches
      }
    ]
  };
}

function buildTinyFishProvider(result) {
  if (result.status === "fulfilled") {
    return { id: "tinyfish_search", name: "TinyFish Search", status: "available" };
  }

  const error = result.reason;
  return {
    id: "tinyfish_search",
    name: "TinyFish Search",
    status: "unavailable",
    reason: error instanceof TinyFishError ? error.code : "provider_error",
    ...(error instanceof TinyFishError && error.upstreamStatus !== undefined
      ? { httpStatus: error.upstreamStatus }
      : {})
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

    const threatAssessment = buildThreatAssessment(threatResult);
    const tinyFishProvider = buildTinyFishProvider(searchResult);
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
    const searchEvidence = searchResult.status === "fulfilled" ? searchResult.value : [];
    const evidence = prepareEvidence(searchEvidence, domain);
    const providerStatuses = {
      tinyfish: tinyFishProvider.status,
      safeBrowsing: threatAssessment.status === "unavailable" ? "unavailable" : "available"
    };
    const verdict = buildVerdict({ threatAssessment, urlSignals, providerStatuses });
    const providers = [tinyFishProvider, ...threatAssessment.providers];

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
        status: searchResult.status === "rejected" ? "partial" : "no_results",
        summary: searchResult.status === "rejected"
          ? "TinyFish search was unavailable. Available independent checks are included below."
          : NO_RESULTS_SUMMARY,
        domain,
        evidence: [],
        investigationType: "web_search",
        demo: false,
        providers,
        verdict,
        threatAssessment,
        urlSignals,
        ethereumAssessment,
        contractAnalysis: effectiveContractAddress ? contractAnalysis : undefined
      });
    }

return res.json({
  status: searchResult.status === "rejected" ? "partial" : "research_available",
  summary: searchResult.status === "rejected"
    ? "TinyFish search was unavailable. Available independent checks are included below."
    : buildSummary(domain, evidence),
  domain,
  evidence,
  investigationType: "web_search",
  demo: false,
  providers,
  verdict,
  threatAssessment,
  urlSignals,
  ethereumAssessment,
  contractAnalysis: effectiveContractAddress ? contractAnalysis : undefined,
  alternativeSites
});
  } catch (error) {
    console.error(
      `[investigations] request failed (errorName=${error && error.name ? error.name : "unknown"})`
    );
    return res.status(500).json({ error: "Something went wrong while running the investigation." });
  }
});

module.exports = router;
