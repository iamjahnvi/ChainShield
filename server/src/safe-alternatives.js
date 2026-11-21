"use strict";

const CATEGORIES = Object.freeze({
  CRYPTO_WALLET: "crypto_wallet",
  CRYPTO_EXCHANGE: "crypto_exchange",
  NFT_MARKETPLACE: "nft_marketplace",
  AIRDROP_PROJECT: "airdrop_project",
  INVESTMENT_PLATFORM: "investment_platform",
  UNKNOWN: "unknown"
});

const CATEGORY_RULES = [
  { category: CATEGORIES.CRYPTO_WALLET, patterns: [/\bcrypto wallet\b/i, /\bwallet provider\b/i, /\bseed phrase\b/i, /\bprivate key\b/i, /\bwallet\b/i] },
  { category: CATEGORIES.CRYPTO_EXCHANGE, patterns: [/\bcrypto(?:currency)? exchange\b/i, /\bdigital asset exchange\b/i, /\bexchange for (?:buying|trading) crypto\b/i, /\bcrypto trading platform\b/i] },
  { category: CATEGORIES.NFT_MARKETPLACE, patterns: [/\bnft marketplace\b/i, /\bmarketplace for (?:nfts|non.fungible tokens)\b/i, /\bbuy and sell nfts\b/i] },
  { category: CATEGORIES.AIRDROP_PROJECT, patterns: [/\bairdrop (?:claim|website|portal|project)\b/i, /\bclaim (?:your )?(?:tokens|airdrop)\b/i, /\btoken claim\b/i, /\bproject announcement\b/i] },
  { category: CATEGORIES.INVESTMENT_PLATFORM, patterns: [/\binvestment platform\b/i, /\bcrypto investment\b/i, /\byield platform\b/i, /\bguaranteed returns\b/i, /\bmanaged crypto portfolio\b/i] }
];

const SOURCE_FRESHNESS_DAYS = 180;
const CATALOG = Object.freeze({
  [CATEGORIES.CRYPTO_WALLET]: [
    {
      name: "MetaMask",
      officialDomain: "metamask.io",
      officialUrl: "https://metamask.io/",
      category: CATEGORIES.CRYPTO_WALLET,
      description: "A self-custody wallet for Ethereum and supported networks.",
      listingSource: "https://ethereum.org/wallets/find-wallet/metamask/",
      verificationSource: "https://github.com/metamask",
      provenanceNote: "Ethereum.org lists the wallet. GitHub's verified-organization profile states that MetaMask controls metamask.io.",
      verifiedAt: "2026-11-20"
    }
  ],
  [CATEGORIES.NFT_MARKETPLACE]: [
    {
      name: "OpenSea",
      officialDomain: "opensea.io",
      officialUrl: "https://opensea.io/",
      category: CATEGORIES.NFT_MARKETPLACE,
      description: "An NFT marketplace for browsing, buying, and selling digital collectibles.",
      listingSource: "https://ethereum.org/apps/categories/collectibles/",
      verificationSource: "https://github.com/ProjectOpenSea",
      provenanceNote: "Ethereum.org lists OpenSea as a marketplace; OpenSea's GitHub organization identifies opensea.io as its website. Directory inclusion is not an endorsement.",
      verifiedAt: "2026-11-20"
    }
  ]
});

function entryText(entry) {
  return `${typeof entry?.title === "string" ? entry.title : ""} ${typeof entry?.snippet === "string" ? entry.snippet : ""}`.trim();
}

function evidenceWeight(entry) {
  if (entry?.category !== "domain_specific") return 0;
  try {
    const parsed = new URL(entry.url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return 0;
  } catch { return 0; }
  return 1;
}

function analyzeCategory(evidence) {
  const scores = Object.fromEntries(CATEGORY_RULES.map(({ category }) => [category, 0]));
  const evidenceByCategory = Object.fromEntries(CATEGORY_RULES.map(({ category }) => [category, []]));

  if (Array.isArray(evidence)) {
    for (const entry of evidence) {
      const weight = evidenceWeight(entry);
      if (!weight) continue;
      const title = typeof entry.title === "string" ? entry.title : "";
      const snippet = typeof entry.snippet === "string" ? entry.snippet : "";
      for (const rule of CATEGORY_RULES) {
        const titleHit = rule.patterns.some((pattern) => pattern.test(title));
        const snippetHit = rule.patterns.some((pattern) => pattern.test(snippet));
        if (titleHit || snippetHit) {
          scores[rule.category] += weight * (titleHit ? 2 : 0) + weight * (snippetHit ? 1 : 0);
          evidenceByCategory[rule.category].push(entry.url);
        }
      }
    }
  }

  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const [winner, winnerScore] = ranked[0] || [CATEGORIES.UNKNOWN, 0];
  const runnerUpScore = ranked[1]?.[1] || 0;
  const total = ranked.reduce((sum, [, score]) => sum + score, 0);
  const confidence = total ? winnerScore / total : 0;
  // A category needs direct, domain-specific evidence and a clear margin over
  // competing purposes. A result that describes several service types stays unknown.
  const confident = winnerScore >= 2 && confidence >= 0.72 && runnerUpScore < 2;
  return {
    category: confident ? winner : CATEGORIES.UNKNOWN,
    confidence: Number(confidence.toFixed(2)),
    evidence: confident ? [...new Set(evidenceByCategory[winner])] : [],
    scores
  };
}

function identifyCategory({ evidence = [] } = {}) {
  return analyzeCategory(evidence).category;
}

function isConcerning(verdict) {
  return ["known_threat_detected", "suspicious_indicators"].includes(verdict?.status);
}

function ageDays(dateString, now) {
  const date = new Date(`${dateString}T00:00:00Z`);
  if (!Number.isFinite(date.getTime())) return Infinity;
  return Math.floor((now.getTime() - date.getTime()) / 86400000);
}

function validCatalogEntry(candidate) {
  try {
    const officialUrl = new URL(candidate.officialUrl);
    const listingSource = new URL(candidate.listingSource);
    const verificationSource = new URL(candidate.verificationSource);
    return officialUrl.protocol === "https:" && officialUrl.hostname === candidate.officialDomain &&
      listingSource.protocol === "https:" && verificationSource.protocol === "https:" &&
      typeof candidate.verifiedAt === "string";
  } catch { return false; }
}

function buildSafeAlternatives({ evidence = [], verdict, now = new Date(), catalog = CATALOG } = {}) {
  const inference = analyzeCategory(evidence);
  let recommendations = [];
  let unavailableReason = "purpose_unclear";

  if (inference.category !== CATEGORIES.UNKNOWN) {
    unavailableReason = "no_current_verified_catalogue_entry";
    if (isConcerning(verdict)) {
      recommendations = (catalog[inference.category] || []).filter((candidate) => {
        if (!validCatalogEntry(candidate)) return false;
        const age = ageDays(candidate.verifiedAt, now);
        return age >= 0 && age <= SOURCE_FRESHNESS_DAYS;
      }).map((candidate) => ({
        name: candidate.name,
        officialDomain: candidate.officialDomain,
        officialUrl: candidate.officialUrl,
        category: candidate.category,
        description: candidate.description,
        verificationStatus: "verified",
        listingStatus: "listed",
        listingSource: candidate.listingSource,
        verificationSource: candidate.verificationSource,
        provenanceNote: candidate.provenanceNote,
        verifiedAt: candidate.verifiedAt,
        reason: `The investigated service appears to be a ${candidate.category.replaceAll("_", " ")}. This alternative is included because an ecosystem directory lists it and the official domain has a separate verification source. This does not establish that the service is safe.`
      }));
    } else unavailableReason = "verdict_does_not_justify_recommendations";
  }

  return {
    status: recommendations.length ? "available" : "unavailable",
    category: inference.category,
    categoryConfidence: inference.confidence,
    categoryEvidence: inference.evidence,
    unavailableReason: recommendations.length ? undefined : unavailableReason,
    recommendations
  };
}

function resolveSafeAlternatives(options, resolver = buildSafeAlternatives) {
  try {
    return resolver(options);
  } catch {
    return {
      status: "unavailable",
      category: CATEGORIES.UNKNOWN,
      categoryConfidence: 0,
      categoryEvidence: [],
      unavailableReason: "provider_error",
      recommendations: []
    };
  }
}

module.exports = { CATEGORIES, analyzeCategory, identifyCategory, buildSafeAlternatives, resolveSafeAlternatives, SOURCE_FRESHNESS_DAYS };
