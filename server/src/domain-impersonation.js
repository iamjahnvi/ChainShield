"use strict";

const { getDomain } = require("tldts");
const { domainToUnicode } = require("node:url");

// Curated reference set. Each entry points to the service's own published
// domain/documentation; similarity is a lead for review, not a threat claim.
const OFFICIAL_DOMAINS = Object.freeze([
  { name: "Ethereum", domain: "ethereum.org", source: "https://ethereum.org/en/" },
  {
    name: "MetaMask",
    domain: "metamask.com",
    domainRole: "primary",
    verificationStatus: "first_party_verified",
    verifiedAt: "2026-11-20",
    provenance: "MetaMask's current first-party Privacy Notice identifies Consensys Software Inc. as MetaMask's operator and lists metamask.com; MetaMask's first-party security guide also identifies metamask.com as an official site.",
    sources: [
      { url: "https://metamask.com/privacy-notice", type: "first_party_privacy_notice", evidence: "Lists https://metamask.com/ among websites operated by MetaMask and names Consensys Software Inc. as operator." },
      { url: "https://support.metamask.com/stay-safe/safety-in-web3/how-do-i-recognize-the-real-metamask-/", type: "first_party_security_guide", evidence: "Names metamask.com and support.metamask.com as official sites." }
    ]
  },
  {
    name: "MetaMask",
    domain: "metamask.io",
    domainRole: "redirect_alias",
    redirectTarget: "metamask.com",
    verificationStatus: "first_party_redirect_verified",
    verifiedAt: "2026-11-20",
    provenance: "Direct first-party navigation to metamask.io resolved to metamask.com during review. MetaMask's current security guide identifies metamask.com as an official site; the .io domain is retained as a verified redirect alias, not treated as the current primary domain.",
    sources: [
      { url: "https://metamask.io/", type: "first_party_redirect_observation", evidence: "The first-party domain redirected to https://metamask.com/ on the review date." },
      { url: "https://support.metamask.com/stay-safe/safety-in-web3/how-do-i-recognize-the-real-metamask-/", type: "first_party_security_guide", evidence: "Current security guide identifies metamask.com as an official site." }
    ]
  },
  { name: "OpenSea", domain: "opensea.io", source: "https://support.opensea.io/" },
  { name: "Coinbase", domain: "coinbase.com", source: "https://help.coinbase.com/" },
  { name: "Uniswap", domain: "uniswap.org", source: "https://docs.uniswap.org/" }
]);

const HOMOGLYPHS = Object.freeze({
  "0": "o", "1": "l", "3": "e", "5": "s", "а": "a", "с": "c",
  "е": "e", "і": "i", "ј": "j", "о": "o", "р": "p", "ѕ": "s",
  "х": "x", "у": "y", "ԁ": "d", "ɡ": "g", "ӏ": "l"
});

function skeleton(value) {
  return String(value).normalize("NFKD").toLowerCase().replace(/[\u0300-\u036f]/g, "")
    .replace(/[0135а-сеіјоpѕхyԁɡӏ]/g, (char) => HOMOGLYPHS[char] || char)
    .replace(/[^a-z0-9]/g, "");
}

function levenshtein(left, right) {
  const row = Array.from({ length: right.length + 1 }, (_, i) => i);
  for (let i = 1; i <= left.length; i += 1) {
    let diagonal = row[0];
    row[0] = i;
    for (let j = 1; j <= right.length; j += 1) {
      const previous = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diagonal + (left[i - 1] === right[j - 1] ? 0 : 1));
      diagonal = previous;
    }
  }
  return row[right.length];
}

function normalizeHostname(input) {
  if (input instanceof URL) input = input.hostname;
  if (typeof input !== "string" || !input.trim()) return null;
  try {
    const url = new URL(input.includes("://") ? input : `https://${input}`);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
    if (!hostname || hostname.includes("_") || hostname.length > 253) return null;
    return hostname;
  } catch {
    return null;
  }
}

function catalogueMatch(official, reason, confidence) {
  const sources = Array.isArray(official.sources)
    ? official.sources
    : official.source
      ? [{ url: official.source, type: "catalogue_reference", evidence: "Existing curated reference entry." }]
      : [];
  return {
    officialName: official.name,
    officialDomain: String(official.domain).toLowerCase(),
    reason,
    ...(confidence ? { confidence } : {}),
    ...(official.domainRole ? { domainRole: official.domainRole } : {}),
    ...(official.redirectTarget ? { redirectTarget: official.redirectTarget } : {}),
    ...(official.verificationStatus ? { verificationStatus: official.verificationStatus } : {}),
    ...(official.verifiedAt ? { verifiedAt: official.verifiedAt } : {}),
    ...(official.provenance ? { provenance: official.provenance } : {}),
    ...(sources.length ? { sources, source: sources[0].url } : {})
  };
}

function analyzeDomainImpersonation(input, catalogue = OFFICIAL_DOMAINS) {
  const hostname = normalizeHostname(input);
  if (!hostname) return { status: "inconclusive", candidateDomain: null, matches: [], explanation: "The submitted value could not be normalized to a valid HTTP(S) hostname." };
  const registrableDomain = getDomain(hostname, { allowPrivateDomains: false });
  if (!registrableDomain) return { status: "inconclusive", candidateDomain: hostname, matches: [], explanation: "A registrable domain could not be determined." };

  const exactOfficialEntries = catalogue.filter((entry) =>
    String(entry.domain || "").toLowerCase() === registrableDomain &&
    typeof entry.verificationStatus === "string" &&
    entry.verificationStatus.startsWith("first_party_")
  );
  if (exactOfficialEntries.length > 0) {
    const isSubdomain = hostname !== registrableDomain;
    const matches = exactOfficialEntries.map((entry) => catalogueMatch(
      entry,
      isSubdomain
        ? `The registrable domain exactly matches a first-party verified MetaMask domain; this is domain recognition only and does not establish that this page or its content is safe.`
        : `The registrable domain exactly matches a first-party verified MetaMask domain; this recognition does not guarantee that every page, download, or linked service is safe.`
    ));
    return {
      status: isSubdomain ? "official_subdomain" : "official_domain",
      candidateDomain: registrableDomain,
      matches,
      explanation: isSubdomain
        ? "The hostname is a subdomain of a first-party verified official domain. Page content and linked services are not thereby verified or guaranteed safe."
        : "The registrable domain is listed by first-party MetaMask sources. This does not guarantee that every page, download, or linked service is safe."
    };
  }

  const candidates = [];
  for (const official of catalogue) {
    const officialDomain = String(official.domain || "").toLowerCase();
    if (!officialDomain || registrableDomain === officialDomain) continue;
    // Only compare the registrable label and require the same public suffix.
    const officialRegistrable = getDomain(officialDomain, { allowPrivateDomains: false });
    if (!officialRegistrable) continue;
    const suffix = officialRegistrable.slice(officialRegistrable.indexOf(".") + 1);
    const candidateSuffix = registrableDomain.slice(registrableDomain.indexOf(".") + 1);
    if (suffix !== candidateSuffix) continue;
    const candidateLabel = registrableDomain.slice(0, -(suffix.length + 1));
    const officialLabel = officialRegistrable.slice(0, -(suffix.length + 1));
    if (Math.min(candidateLabel.length, officialLabel.length) < 4) continue;
    const readableCandidateLabel = domainToUnicode(candidateLabel) || candidateLabel;
    const distance = levenshtein(skeleton(readableCandidateLabel), skeleton(officialLabel));
    const homograph = skeleton(readableCandidateLabel) === skeleton(officialLabel) && readableCandidateLabel !== officialLabel;
    const threshold = Math.max(1, Math.floor(officialLabel.length * 0.2));
    if (!homograph && (distance === 0 || distance > threshold)) continue;
    candidates.push(catalogueMatch(
      official,
      homograph ? "The registrable label uses characters that normalize to the same visual-comparison form as the official label." : `The registrable label differs from the official label by ${distance} character edit${distance === 1 ? "" : "s"}.`,
      homograph ? "high" : distance === 1 ? "medium" : "low"
    ));
  }
  const confidenceOrder = { high: 0, medium: 1, low: 2 };
  candidates.sort((a, b) => confidenceOrder[a.confidence] - confidenceOrder[b.confidence]);
  return {
    status: candidates.length ? "possible_lookalike" : "no_match",
    candidateDomain: registrableDomain,
    matches: candidates.slice(0, 3),
    explanation: candidates.length
      ? "A similarity to a curated official domain was found. This is an indicator for review, not proof of impersonation or malicious intent."
      : "No close match was found in the small curated reference set. This does not rule out impersonation of other services."
  };
}

module.exports = { OFFICIAL_DOMAINS, analyzeDomainImpersonation, levenshtein, normalizeHostname, skeleton };
