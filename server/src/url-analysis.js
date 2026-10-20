const { isIP } = require("node:net");

const MANY_SUBDOMAIN_LABELS_THRESHOLD = 4;

function createFinding(ruleId, explanation, label, value) {
  return {
    ruleId,
    severity: "low",
    explanation,
    observedFeature: { label, value }
  };
}

function analyzeUrl(url) {
  if (!(url instanceof URL) || (url.protocol !== "http:" && url.protocol !== "https:")) {
    throw new TypeError("analyzeUrl requires a validated HTTP or HTTPS URL.");
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const findings = [];
  const ipHostname = hostname.replace(/^\[|\]$/g, "");
  const ipVersion = isIP(ipHostname);

  if (ipVersion !== 0) {
    findings.push(
      createFinding(
        "ip_address_hostname",
        "The URL uses an IP address instead of a conventional domain. Review the destination; this alone does not indicate a threat.",
        "IP version",
        String(ipVersion)
      )
    );
    return findings;
  }

  const labels = hostname.split(".");
  const punycodeLabels = labels.filter((label) => label.startsWith("xn--"));
  for (const label of punycodeLabels) {
    findings.push(
      createFinding(
        "punycode_hostname_label",
        "The hostname contains an internationalized punycode label. Review the displayed domain carefully; this alone does not indicate a threat.",
        "Punycode label",
        label
      )
    );
  }

  const subdomainLabelCount = Math.max(labels.length - 2, 0);
  if (subdomainLabelCount >= MANY_SUBDOMAIN_LABELS_THRESHOLD) {
    findings.push(
      createFinding(
        "many_subdomain_labels",
        "Four or more labels precede the final two hostname labels. This unusual depth can occur on legitimate sites and is not proof of a threat.",
        "Labels before final two",
        String(subdomainLabelCount)
      )
    );
  }

  return findings;
}

module.exports = { analyzeUrl, MANY_SUBDOMAIN_LABELS_THRESHOLD };
