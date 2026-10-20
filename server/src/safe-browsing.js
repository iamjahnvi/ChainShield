const SAFE_BROWSING_ENDPOINT =
  "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const DEFAULT_TIMEOUT_MS = 6000;
const THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING"];
const MAX_CACHE_ENTRIES = 500;
const positiveCache = new Map();

class SafeBrowsingError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SafeBrowsingError";
    this.code = code;
  }
}

const defaultFetch = (...args) => globalThis.fetch(...args);
let activeFetch = defaultFetch;

function setSafeBrowsingFetch(fetchImpl) {
  activeFetch = typeof fetchImpl === "function" ? fetchImpl : defaultFetch;
}

function getApiKey(env = process.env) {
  const key = env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (typeof key !== "string" || key.trim() === "") {
    throw new SafeBrowsingError("config_missing", "Safe Browsing is not configured.");
  }
  return key.trim();
}

function getTimeoutMs(env = process.env) {
  const raw = Number(env.GOOGLE_SAFE_BROWSING_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
}

function parseCacheDuration(value) {
  if (typeof value !== "string") {
    return null;
  }

  const match = /^(\d+(?:\.\d+)?)s$/.exec(value);
  if (!match) {
    return null;
  }

  const durationMs = Number(match[1]) * 1000;
  return Number.isFinite(durationMs) && durationMs > 0 ? durationMs : null;
}

function normalizeMatches(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new SafeBrowsingError("bad_response", "Safe Browsing returned an invalid response.");
  }

  const matches = payload.matches === undefined ? [] : payload.matches;
  if (!Array.isArray(matches)) {
    throw new SafeBrowsingError("bad_response", "Safe Browsing returned invalid matches.");
  }

  const normalizedMatches = matches.map((match) => {
    if (
      !match ||
      typeof match !== "object" ||
      !THREAT_TYPES.includes(match.threatType) ||
      !match.threat ||
      typeof match.threat.url !== "string"
    ) {
      throw new SafeBrowsingError("bad_response", "Safe Browsing returned an invalid match.");
    }

    let matchedUrl;
    try {
      matchedUrl = new URL(match.threat.url);
    } catch {
      throw new SafeBrowsingError("bad_response", "Safe Browsing returned an invalid match URL.");
    }

    if (matchedUrl.protocol !== "http:" && matchedUrl.protocol !== "https:") {
      throw new SafeBrowsingError("bad_response", "Safe Browsing returned an invalid match URL.");
    }

    return {
      threatType: match.threatType,
      matchedUrl: matchedUrl.toString(),
      cacheDurationMs: parseCacheDuration(match.cacheDuration)
    };
  });

  return normalizedMatches;
}

async function checkSafeBrowsing(submittedUrl, options = {}) {
  const env = options.env || process.env;
  const apiKey = getApiKey(env);
  const fetchImpl = options.fetchImpl || activeFetch;
  const timeoutMs = options.timeoutMs || getTimeoutMs(env);
  const url = new URL(submittedUrl);
  url.username = "";
  url.password = "";
  url.hash = "";
  const cacheKey = url.toString();
  const cached = positiveCache.get(cacheKey);
  if (cached) {
    if (cached.expiresAt > Date.now()) {
      return cached.matches.map(({ threatType, matchedUrl }) => ({
        threatType,
        matchedUrl
      }));
    }
    positiveCache.delete(cacheKey);
  }

  const endpoint = new URL(SAFE_BROWSING_ENDPOINT);
  endpoint.searchParams.set("key", apiKey);

  const controller = new AbortController();
  let timer;
  const timeoutError = new SafeBrowsingError("timeout", "Safe Browsing lookup timed out.");
  const timeoutPromise = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(timeoutError);
    }, timeoutMs);
  });

  try {
    const requestPromise = (async () => {
      let response;
      try {
        response = await fetchImpl(endpoint.toString(), {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({
            client: { clientId: "chainshield", clientVersion: "0.1.0" },
            threatInfo: {
              threatTypes: THREAT_TYPES,
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url: url.toString() }]
            }
          }),
          signal: controller.signal,
          redirect: "error"
        });
      } catch {
        if (controller.signal.aborted) {
          throw timeoutError;
        }
        throw new SafeBrowsingError("network", "Safe Browsing lookup failed.");
      }

      if (!response || typeof response.ok !== "boolean") {
        throw new SafeBrowsingError("bad_response", "Safe Browsing returned an unreadable response.");
      }
      if (!response.ok) {
        throw new SafeBrowsingError("upstream", "Safe Browsing returned an error.");
      }

      let payload;
      try {
        payload = await response.json();
      } catch {
        if (controller.signal.aborted) {
          throw timeoutError;
        }
        throw new SafeBrowsingError("bad_response", "Safe Browsing returned malformed JSON.");
      }

      const normalizedMatches = normalizeMatches(payload);
      if (
        normalizedMatches.length > 0 &&
        normalizedMatches.every((match) => match.cacheDurationMs !== null)
      ) {
        const cacheDurationMs = Math.min(
          ...normalizedMatches.map((match) => match.cacheDurationMs)
        );
        if (positiveCache.size >= MAX_CACHE_ENTRIES) {
          positiveCache.delete(positiveCache.keys().next().value);
        }
        positiveCache.set(cacheKey, {
          expiresAt: Date.now() + cacheDurationMs,
          matches: normalizedMatches
        });
      }
      return normalizedMatches.map(({ threatType, matchedUrl }) => ({
        threatType,
        matchedUrl
      }));
    })();

    return await Promise.race([requestPromise, timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  SAFE_BROWSING_ENDPOINT,
  SafeBrowsingError,
  checkSafeBrowsing,
  setSafeBrowsingFetch
};
