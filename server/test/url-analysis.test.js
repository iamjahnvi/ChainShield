const assert = require("node:assert/strict");
const { test } = require("node:test");
const { analyzeUrl, MANY_SUBDOMAIN_LABELS_THRESHOLD } = require("../src/url-analysis");

function findingsFor(value) {
  return analyzeUrl(new URL(value));
}

test("flags IPv4 and IPv6 hosts without including the submitted URL", () => {
  for (const [url, version] of [
    ["https://user:password@192.0.2.10/path?token=secret", "4"],
    ["http://user:password@[2001:db8::1]:8080/path?token=secret", "6"]
  ]) {
    const findings = findingsFor(url);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].ruleId, "ip_address_hostname");
    assert.equal(findings[0].severity, "low");
    assert.deepEqual(findings[0].observedFeature, {
      label: "IP version",
      value: version
    });
    assert.doesNotMatch(JSON.stringify(findings), /user|password|secret|\/path|\?/i);
  }
});

test("flags explicit punycode labels for review without calling them malicious", () => {
  const findings = findingsFor(
    "https://user:password@xn--bcher-kva.example/path?session=private"
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "punycode_hostname_label");
  assert.equal(findings[0].observedFeature.value, "xn--bcher-kva");
  assert.match(findings[0].explanation, /does not indicate a threat/i);
  assert.doesNotMatch(JSON.stringify(findings), /user|password|private|\/path|\?/i);
});

test("flags four or more labels before the final two hostname labels", () => {
  const labels = ["one", "two", "three", "four", "example", "com"];
  const findings = findingsFor(`https://${labels.join(".")}/`);
  assert.equal(MANY_SUBDOMAIN_LABELS_THRESHOLD, 4);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "many_subdomain_labels");
  assert.deepEqual(findings[0].observedFeature, {
    label: "Labels before final two",
    value: "4"
  });
});

test("does not flag ordinary domains or hostnames below the conservative depth threshold", () => {
  for (const url of [
    "https://example.com/",
    "https://www.example.com/path?q=ordinary",
    "https://one.two.three.example.com/"
  ]) {
    assert.deepEqual(findingsFor(url), []);
  }
});

test("does not mistake an IP hostname for many subdomain labels", () => {
  const findings = findingsFor("https://192.0.2.1/");
  assert.deepEqual(findings.map((finding) => finding.ruleId), ["ip_address_hostname"]);
});

test("hostname labels are evaluated as whole labels, not text fragments", () => {
  const findings = findingsFor("https://notxn--label.example.com/");
  assert.deepEqual(findings, []);
});

test("rejects values that are not already validated HTTP or HTTPS URL objects", () => {
  assert.throws(() => analyzeUrl("https://example.com"), TypeError);
  assert.throws(() => analyzeUrl(new URL("file:///tmp/example")), TypeError);
});
