const express = require("express");
const {
  TinyFishError,
  buildInvestigationQuery,
  searchTinyFish
} = require("../tinyfish");
const { CATEGORIES, prepareEvidence } = require("../classification");

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
  const { url: submittedUrl } = req.body || {};

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

  const domain = url.hostname;

  try {
    const results = await searchTinyFish(buildInvestigationQuery(domain));
    const evidence = prepareEvidence(results, domain);

    if (evidence.length === 0) {
      return res.json({
        status: "no_results",
        summary: NO_RESULTS_SUMMARY,
        domain,
        evidence: [],
        investigationType: "web_search",
        demo: false
      });
    }

    return res.json({
      status: "research_available",
      summary: buildSummary(domain, evidence),
      domain,
      evidence,
      investigationType: "web_search",
      demo: false
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
