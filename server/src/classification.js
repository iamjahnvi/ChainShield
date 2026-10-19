const CATEGORIES = {
  DOMAIN_SPECIFIC: "domain_specific",
  GENERAL_INFORMATION: "general_information",
  IRRELEVANT_OR_UNCLEAR: "irrelevant_or_unclear"
};

const SECURITY_TERMS = [
  "scam",
  "phish",
  "fraud",
  "impersonat",
  "malware",
  "ransomware",
  "advisory",
  "breach",
  "stolen",
  "leaked",
  "spoof",
  "hijack",
  "suspicious",
  "cybercrime",
  "identity theft",
  "unsafe",
  "blacklist",
  "threat"
];

const TRACKING_PARAMS = [
  "gclid",
  "fbclid",
  "msclkid",
  "igshid",
  "mc_cid",
  "mc_eid"
];

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeHost(hostname) {
  if (typeof hostname !== "string") {
    return "";
  }
  let host = hostname.trim().toLowerCase();
  if (host.endsWith(".")) {
    host = host.slice(0, -1);
  }
  return host;
}

function isValidHttpUrl(value) {
  if (typeof value !== "string" || value.trim() === "") {
    return false;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function canonicalizeUrl(value) {
  if (!isValidHttpUrl(value)) {
    return "";
  }

  const parsed = new URL(value.trim());
  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  const host = parsed.hostname.toLowerCase();
  const port = parsed.port ? `:${parsed.port}` : "";
  const searchParams =
    parsed.search === ""
      ? []
      : parsed.search
          .slice(1)
          .split("&")
          .filter((parameter) => {
            const rawKey = parameter.split("=", 1)[0];
            let key;
            try {
              key = decodeURIComponent(rawKey.replace(/\+/g, " ")).toLowerCase();
            } catch {
              return true;
            }
            return !key.startsWith("utm_") && !TRACKING_PARAMS.includes(key);
          });
  const search =
    searchParams.length > 0
      ? `?${searchParams.join("&")}`
      : parsed.search === "" && parsed.href.includes("?")
        ? "?"
        : "";

  return `${scheme}://${host}${port}${parsed.pathname}${search}${parsed.hash}`;
}

function dedupeByUrl(entries) {
  const seen = new Set();
  const output = [];

  for (const entry of entries) {
    const key =
      typeof entry.url === "string" && entry.url !== ""
        ? canonicalizeUrl(entry.url)
        : "";

    if (key !== "") {
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
    }

    output.push(entry);
  }

  return output;
}

function extractHost(entry) {
  if (typeof entry.url !== "string" || entry.url === "") {
    return "";
  }
  try {
    return normalizeHost(new URL(entry.url).hostname);
  } catch {
    return "";
  }
}

function hostnameMentioned(text, host) {
  if (text === "" || host === "") {
    return false;
  }
  const pattern = new RegExp(`(^|[^a-z0-9.-])${escapeRegExp(host)}($|[^a-z0-9.-])`);
  return pattern.test(text);
}

const HOST_CONTEXT_WORDS = [
  "official",
  "website",
  "homepage",
  "url",
  "report",
  "review",
  "scam",
  "phishing",
  "fraud",
  "impersonation",
  "malware",
  "spoofing",
  "hijack",
  "blacklist",
  "down",
  "outage",
  "owned",
  "compromised",
  "suspicious"
];

function hasHostContextWord(window) {
  return HOST_CONTEXT_WORDS.some(
    (word) =>
      new RegExp(`(^|[^a-z0-9])${word}s?($|[^a-z0-9])`).test(window)
  );
}

function isDomainFocusedReport(text, host) {
  if (text === "" || host === "") {
    return false;
  }

  const pattern = new RegExp(`(^|[^a-z0-9.-])${escapeRegExp(host)}($|[^a-z0-9.-])`);
  const match = pattern.exec(text);
  if (!match) {
    return false;
  }

  const mentionIndex = match.index + match[1].length;
  const window = text.slice(
    mentionIndex + host.length,
    mentionIndex + host.length + 36
  );

  return hasHostContextWord(window);
}

function hasSecurityTerm(text) {
  return SECURITY_TERMS.some((term) => text.includes(term));
}

function classifyEntry(entry, investigatedHost) {
  const host = normalizeHost(investigatedHost);
  const resultHost = extractHost(entry);
  const text = (
    `${typeof entry.title === "string" ? entry.title : ""} ` +
    `${typeof entry.snippet === "string" ? entry.snippet : ""}`
  ).toLowerCase();

  const onExactHost = host !== "" && resultHost === host;
  const onSubdomain =
    host !== "" && resultHost !== "" && resultHost.endsWith(`.${host}`);

  if (onExactHost || onSubdomain) {
    return {
      category: CATEGORIES.DOMAIN_SPECIFIC,
      categoryReason: onExactHost
        ? "The source URL is on the investigated hostname. Relevance to the domain does not establish maliciousness."
        : "The source URL is on a subdomain of the investigated hostname. Relevance to the domain does not establish maliciousness."
    };
  }

  const mentionsHost = hostnameMentioned(text, host);
  if (mentionsHost && isDomainFocusedReport(text, host)) {
    return {
      category: CATEGORIES.DOMAIN_SPECIFIC,
      categoryReason:
        "The title or snippet is about the investigated hostname itself. Relevance to the domain does not establish maliciousness."
    };
  }

  const securityTopic = hasSecurityTerm(text);
  const onParentDomain =
    host !== "" && resultHost !== "" && host.endsWith(`.${resultHost}`);

  if (onParentDomain) {
    if (securityTopic) {
      return {
        category: CATEGORIES.GENERAL_INFORMATION,
        categoryReason:
          "Security-related content about the parent domain, not the investigated hostname."
      };
    }
    return {
      category: CATEGORIES.IRRELEVANT_OR_UNCLEAR,
      categoryReason:
        "Refers to the parent domain rather than the investigated hostname."
    };
  }

  if (mentionsHost) {
    if (securityTopic) {
      return {
        category: CATEGORIES.GENERAL_INFORMATION,
        categoryReason:
          "The hostname appears only as a passing mention in an otherwise general source."
      };
    }
    return {
      category: CATEGORIES.IRRELEVANT_OR_UNCLEAR,
      categoryReason:
        "The hostname appears only as a passing mention; the result is not about the investigated hostname."
    };
  }

  if (securityTopic) {
    return {
      category: CATEGORIES.GENERAL_INFORMATION,
      categoryReason:
        "General security-related source that does not mention the investigated hostname."
    };
  }

  return {
    category: CATEGORIES.IRRELEVANT_OR_UNCLEAR,
    categoryReason: "No clear connection to the investigated hostname."
  };
}

function prepareEvidence(entries, investigatedHost) {
  const deduped = dedupeByUrl(entries);
  for (const entry of deduped) {
    Object.assign(entry, classifyEntry(entry, investigatedHost));
  }
  return deduped;
}

module.exports = {
  CATEGORIES,
  canonicalizeUrl,
  classifyEntry,
  dedupeByUrl,
  hostnameMentioned,
  normalizeHost,
  prepareEvidence
};
