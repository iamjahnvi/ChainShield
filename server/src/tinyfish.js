const TINYFISH_SEARCH_ENDPOINT = "https://api.search.tinyfish.ai";
const DEFAULT_TIMEOUT_MS = 8000;

class TinyFishError extends Error {
  constructor(code, message, { upstreamStatus } = {}) {
    super(message);
    this.name = "TinyFishError";
    this.code = code;
    if (upstreamStatus !== undefined) {
      this.upstreamStatus = upstreamStatus;
    }
  }
}

const defaultFetch = (...args) => globalThis.fetch(...args);
let activeFetch = defaultFetch;

function setSearchFetch(fetchImpl) {
  activeFetch = typeof fetchImpl === "function" ? fetchImpl : defaultFetch;
}

function getApiKey(env = process.env) {
  const key = env.TINYFISH_API_KEY;
  if (typeof key !== "string" || key.trim() === "") {
    throw new TinyFishError("config_missing", "TINYFISH_API_KEY is not configured.");
  }
  return key.trim();
}

function getTimeoutMs(env = process.env) {
  const raw = Number(env.TINYFISH_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
}

function buildInvestigationQuery(hostname) {
  return (
    `${hostname} scam phishing impersonation fraud ` +
    "security report"
  );
}

function normalizeUrl(value) {
  if (typeof value !== "string") {
    return "";
  }

  const trimmed = value.trim();
  if (trimmed === "") {
    return "";
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.toString();
    }
  } catch {
    return "";
  }

  return "";
}

function normalizeEvidence(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new TinyFishError("bad_response", "Search response was not a JSON object.");
  }

  const { results } = payload;
  if (results === undefined || results === null) {
    throw new TinyFishError("bad_response", "Search response results field was missing.");
  }

  if (!Array.isArray(results)) {
    throw new TinyFishError("bad_response", "Search response results field was not an array.");
  }

  const evidence = [];

  for (const item of results) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      continue;
    }

    const title = typeof item.title === "string" ? item.title.trim() : "";
    const url = normalizeUrl(item.url);

    if (title === "" && url === "") {
      continue;
    }

    const entry = { title: title === "" ? url : title, source: "TinyFish Search" };

    if (url !== "") {
      entry.url = url;
    }

    const snippet = typeof item.snippet === "string" ? item.snippet.trim() : "";
    if (snippet !== "") {
      entry.snippet = snippet;
    }

    if (typeof item.position === "number" && Number.isFinite(item.position)) {
      entry.position = item.position;
    }

    const siteName = typeof item.site_name === "string" ? item.site_name.trim() : "";
    if (siteName !== "") {
      entry.siteName = siteName;
    }

    evidence.push(entry);
  }

  return evidence;
}

async function searchTinyFish(query, options = {}) {
  const env = options.env || process.env;
  const apiKey = getApiKey(env);
  const fetchImpl = options.fetchImpl || activeFetch;
  const timeoutMs = options.timeoutMs || getTimeoutMs(env);

  const endpoint = `${TINYFISH_SEARCH_ENDPOINT}?query=${encodeURIComponent(query)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response;

    try {
      response = await fetchImpl(endpoint, {
        method: "GET",
        headers: { "X-API-Key": apiKey, Accept: "application/json" },
        signal: controller.signal,
        redirect: "error"
      });
    } catch {
      if (controller.signal.aborted) {
        throw new TinyFishError("timeout", "Search request timed out.");
      }
      throw new TinyFishError("network", "Search request failed to reach the search service.");
    }

    if (!response || typeof response.ok !== "boolean") {
      throw new TinyFishError("bad_response", "Search service returned an unreadable response.");
    }

    if (response.status === 429) {
      throw new TinyFishError("rate_limited", "Search service rate limit reached.", {
        upstreamStatus: 429
      });
    }

    if (!response.ok) {
      throw new TinyFishError("upstream", "Search service returned an error.", {
        upstreamStatus: response.status
      });
    }

    let payload;
    try {
      payload = await response.json();
    } catch {
      if (controller.signal.aborted) {
        throw new TinyFishError("timeout", "Search request timed out.");
      }
      throw new TinyFishError("bad_response", "Search service returned malformed JSON.");
    }

    return normalizeEvidence(payload);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  TINYFISH_SEARCH_ENDPOINT,
  DEFAULT_TIMEOUT_MS,
  TinyFishError,
  buildInvestigationQuery,
  normalizeEvidence,
  searchTinyFish,
  setSearchFetch
};
