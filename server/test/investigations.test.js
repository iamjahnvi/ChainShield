const assert = require("node:assert/strict");
const { after, afterEach, before, beforeEach, test } = require("node:test");
const app = require("../src/app");
const {
  TINYFISH_SEARCH_ENDPOINT,
  setSearchFetch
} = require("../src/tinyfish");
const {
  SAFE_BROWSING_ENDPOINT,
  setSafeBrowsingFetch
} = require("../src/safe-browsing");
const { setEthereumRpcFetch } = require("../src/ethereum-rpc");

const TEST_API_KEY = "unit-test-secret-key-must-never-leak";
const TEST_SAFE_BROWSING_KEY = "safe-browsing-test-key-must-never-leak";

const originalConsoleError = console.error;
const originalConsoleInfo = console.info;
const originalConsoleWarn = console.warn;
const originalApiKey = process.env.TINYFISH_API_KEY;
const originalTimeoutMs = process.env.TINYFISH_TIMEOUT_MS;
const originalSafeBrowsingApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const originalSafeBrowsingTimeoutMs = process.env.GOOGLE_SAFE_BROWSING_TIMEOUT_MS;
const originalEthereumRpcUrl = process.env.ETH_RPC_URL;

let server;
let baseUrl;
let capturedLogs;

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload
  };
}

function guardFetch() {
  setSearchFetch(async () => {
    throw new Error("No TinyFish fetch mock was configured for this test.");
  });
  setSafeBrowsingFetch(async () => jsonResponse({}));
  setEthereumRpcFetch(async () => {
    throw new Error("No Ethereum RPC fetch mock was configured for this test.");
  });
}

function rpcJsonResponse(id, result) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id, result }), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

async function postInvestigation(body) {
  const response = await fetch(`${baseUrl}/api/investigations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  return { response, body: await response.json() };
}

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  guardFetch();
});

after(async () => {
  setSearchFetch(null);
  setSafeBrowsingFetch(null);
  setEthereumRpcFetch(null);
  process.env.TINYFISH_API_KEY = originalApiKey;
  process.env.TINYFISH_TIMEOUT_MS = originalTimeoutMs;
  process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalSafeBrowsingApiKey;
  process.env.GOOGLE_SAFE_BROWSING_TIMEOUT_MS = originalSafeBrowsingTimeoutMs;
  process.env.ETH_RPC_URL = originalEthereumRpcUrl;
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

beforeEach(() => {
  process.env.TINYFISH_API_KEY = TEST_API_KEY;
  delete process.env.TINYFISH_TIMEOUT_MS;
  process.env.GOOGLE_SAFE_BROWSING_API_KEY = TEST_SAFE_BROWSING_KEY;
  delete process.env.GOOGLE_SAFE_BROWSING_TIMEOUT_MS;
  process.env.ETH_RPC_URL = "https://rpc.example/route-test-credential";
  capturedLogs = [];
  console.error = (...args) => {
    capturedLogs.push(args.map(String).join(" "));
  };
  console.info = (...args) => {
    capturedLogs.push(args.map(String).join(" "));
  };
  console.warn = (...args) => {
    capturedLogs.push(args.map(String).join(" "));
  };
});

afterEach(() => {
  console.error = originalConsoleError;
  console.info = originalConsoleInfo;
  console.warn = originalConsoleWarn;
  guardFetch();
});

test("valid investigation request returns validated TinyFish results", async () => {
  let captured;
  let safeBrowsingRequest;
  let ethereumRpcCalls = 0;
  setSearchFetch(async (url, init) => {
    captured = { url, init };
    return jsonResponse({
      results: [
        {
          position: 1,
          site_name: "example-official",
          title: "  Example Inc — Official Site  ",
          snippet: " Example official website. ",
          url: "https://www.example.com/about"
        },
        {
          title: "Security advisory",
          url: "https://cert.example.org/advisory/123",
          snippet: "Advisory text",
          site_name: "CERT"
        },
        {
          title: "",
          url: "https://plain.example.net",
          snippet: null,
          position: "three"
        },
        { title: "Mention without link", snippet: "no url here" },
        { title: "Unsafe link", url: "javascript:alert(1)" },
        null,
        "string-entry"
      ]
    });
  });
  setSafeBrowsingFetch(async (url, init) => {
    safeBrowsingRequest = { url, init };
    return jsonResponse({});
  });
  setEthereumRpcFetch(async () => {
    ethereumRpcCalls += 1;
    throw new Error("Ethereum RPC should not be called without a contract address.");
  });

  const { response, body } = await postInvestigation({
    url: "https://www.example.com/path?q=demo"
  });

  assert.equal(response.status, 200);
  assert.equal(body.status, "research_available");
  assert.equal(body.domain, "www.example.com");
  assert.equal(body.investigationType, "web_search");
  assert.equal(body.demo, false);
  assert.equal(body.threatAssessment.status, "no_match");
  assert.equal(body.threatAssessment.providers[0].id, "google_safe_browsing");
  assert.equal(body.threatAssessment.providers[0].scope, "submitted_url");
  assert.deepEqual(body.urlSignals, { findings: [] });
  assert.deepEqual(body.ethereumAssessment, { status: "not_requested" });
  assert.equal(ethereumRpcCalls, 0);
  assert.match(body.summary, /do not establish whether the website is safe or malicious/i);

  assert.equal(body.evidence.length, 5);

  assert.deepEqual(body.evidence[0], {
    title: "Example Inc — Official Site",
    url: "https://www.example.com/about",
    snippet: "Example official website.",
    source: "TinyFish Search",
    position: 1,
    siteName: "example-official",
    category: "domain_specific",
    categoryReason:
      "The source URL is on the investigated hostname. Relevance to the domain does not establish maliciousness."
  });

  assert.deepEqual(body.evidence[1], {
    title: "Security advisory",
    url: "https://cert.example.org/advisory/123",
    snippet: "Advisory text",
    source: "TinyFish Search",
    siteName: "CERT",
    category: "general_information",
    categoryReason:
      "General security-related source that does not mention the investigated hostname."
  });
  assert.ok(!("position" in body.evidence[1]));

  assert.deepEqual(body.evidence[2], {
    title: "https://plain.example.net/",
    url: "https://plain.example.net/",
    source: "TinyFish Search",
    category: "irrelevant_or_unclear",
    categoryReason: "No clear connection to the investigated hostname."
  });
  assert.ok(!("snippet" in body.evidence[2]));
  assert.ok(!("position" in body.evidence[2]));
  assert.ok(!("siteName" in body.evidence[2]));

  assert.deepEqual(body.evidence[3], {
    title: "Mention without link",
    snippet: "no url here",
    source: "TinyFish Search",
    category: "irrelevant_or_unclear",
    categoryReason: "No clear connection to the investigated hostname."
  });
  assert.ok(!("url" in body.evidence[3]));

  assert.deepEqual(body.evidence[4], {
    title: "Unsafe link",
    source: "TinyFish Search",
    category: "general_information",
    categoryReason:
      "General security-related source that does not mention the investigated hostname."
  });
  assert.ok(!("url" in body.evidence[4]));

  assert.ok(captured);
  assert.ok(captured.url.startsWith(`${TINYFISH_SEARCH_ENDPOINT}?query=`));
  const query = decodeURIComponent(
    captured.url.slice(`${TINYFISH_SEARCH_ENDPOINT}?query=`.length)
  );
  assert.ok(query.includes("www.example.com"));
  assert.ok(query.includes("security report"));
  assert.ok(query.includes("impersonation"));
  assert.ok(query.includes("scam"));
  assert.ok(query.includes("phishing"));
  assert.ok(query.includes("fraud"));
  assert.ok(!captured.url.includes(TEST_API_KEY));

  assert.equal(captured.init.method, "GET");
  assert.equal(captured.init.headers["X-API-Key"], TEST_API_KEY);
  assert.equal(captured.init.redirect, "error");
  assert.ok(safeBrowsingRequest.url.startsWith(SAFE_BROWSING_ENDPOINT));
  assert.ok(safeBrowsingRequest.url.includes(encodeURIComponent(TEST_SAFE_BROWSING_KEY)));
  assert.equal(safeBrowsingRequest.init.method, "POST");
  assert.equal(
    JSON.parse(safeBrowsingRequest.init.body).threatInfo.threatEntries[0].url,
    "https://www.example.com/path?q=demo"
  );

  assert.ok(!JSON.stringify(body).includes(TEST_API_KEY));
  assert.ok(!JSON.stringify(body).includes(TEST_SAFE_BROWSING_KEY));
  assert.ok(capturedLogs.some((entry) => entry.includes("httpStatus=200, category=no_match")));
  assert.ok(!capturedLogs.join("\n").includes("/path?q=demo"));
});

test("optional Ethereum assessment reports network, block, and bytecode separately", async () => {
  setSearchFetch(async () => jsonResponse({ results: [] }));
  setSafeBrowsingFetch(async () => jsonResponse({}));
  const rpcRequests = [];
  setEthereumRpcFetch(async (endpoint, init) => {
    const request = JSON.parse(init.body);
    rpcRequests.push({ endpoint, init, request });
    const results = {
      eth_chainId: "0x1",
      eth_blockNumber: "0x1234",
      eth_getCode: "0x60016000"
    };
    return rpcJsonResponse(request.id, results[request.method]);
  });

  const { response, body } = await postInvestigation({
    url: "https://example.com",
    contractAddress: "0x1234567890abcdef1234567890abcdef12345678"
  });

  assert.equal(response.status, 200);
  assert.equal(body.status, "no_results");
  assert.equal(body.threatAssessment.status, "no_match");
  assert.deepEqual(body.ethereumAssessment, {
    status: "available",
    address: "0x1234567890abcdef1234567890abcdef12345678",
    chainId: "0x1",
    latestBlock: "0x1234",
    codeStatus: "bytecode_present"
  });
  assert.equal(rpcRequests.length, 3);
  assert.ok(rpcRequests.every((request) => request.endpoint === process.env.ETH_RPC_URL));
  assert.ok(rpcRequests.every((request) => request.init.redirect === "error"));
  assert.deepEqual(
    rpcRequests.find(({ request }) => request.method === "eth_getCode").request.params,
    ["0x1234567890abcdef1234567890abcdef12345678", "latest"]
  );
  assert.ok(!JSON.stringify(body).includes("60016000"));
  assert.ok(!JSON.stringify(body).includes("route-test-credential"));
  assert.ok(!capturedLogs.join("\n").includes("route-test-credential"));
});

test("invalid contract addresses are rejected before any provider request", async () => {
  let providerCalls = 0;
  setSearchFetch(async () => {
    providerCalls += 1;
    return jsonResponse({ results: [] });
  });
  setSafeBrowsingFetch(async () => {
    providerCalls += 1;
    return jsonResponse({});
  });
  setEthereumRpcFetch(async () => {
    providerCalls += 1;
    return rpcJsonResponse(1, "0x1");
  });

  const { response, body } = await postInvestigation({
    url: "https://example.com",
    contractAddress: "0x1234"
  });

  assert.equal(response.status, 400);
  assert.match(body.error, /contractAddress/);
  assert.equal(providerCalls, 0);
});

test("Ethereum RPC failures and missing configuration do not break other results", async (t) => {
  await t.test("provider error is isolated", async () => {
    setSearchFetch(async () => jsonResponse({ results: [] }));
    setSafeBrowsingFetch(async () => jsonResponse({}));
    setEthereumRpcFetch(async (_endpoint, init) => {
      const { id } = JSON.parse(init.body);
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: "private" } }),
        { status: 200 }
      );
    });

    const { response, body } = await postInvestigation({
      url: "https://example.com",
      contractAddress: "0x1234567890abcdef1234567890abcdef12345678"
    });

    assert.equal(response.status, 200);
    assert.equal(body.status, "no_results");
    assert.equal(body.threatAssessment.status, "no_match");
    assert.equal(body.ethereumAssessment.status, "unavailable");
    assert.equal(body.ethereumAssessment.reason, "rpc_error");
    assert.ok(!JSON.stringify(body).includes("private"));
    assert.ok(capturedLogs.some((entry) => entry.includes("category=rpc_error")));
    assert.ok(!capturedLogs.join("\n").includes("route-test-credential"));
  });

  await t.test("missing configuration is isolated", async () => {
    delete process.env.ETH_RPC_URL;
    setSearchFetch(async () => jsonResponse({ results: [] }));
    setSafeBrowsingFetch(async () => jsonResponse({}));
    let rpcCalled = false;
    setEthereumRpcFetch(async () => {
      rpcCalled = true;
      return rpcJsonResponse(1, "0x1");
    });

    const { response, body } = await postInvestigation({
      url: "https://example.com",
      contractAddress: "0x1234567890abcdef1234567890abcdef12345678"
    });

    assert.equal(response.status, 200);
    assert.equal(body.threatAssessment.status, "no_match");
    assert.equal(body.ethereumAssessment.status, "unavailable");
    assert.equal(body.ethereumAssessment.reason, "config_missing");
    assert.equal(rpcCalled, false);
  });
});

test("empty search results return a neutral no_results response", async () => {
  setSearchFetch(async () => jsonResponse({ results: [] }));

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 200);
  assert.equal(body.status, "no_results");
  assert.deepEqual(body.evidence, []);
  assert.equal(body.domain, "example.com");
  assert.equal(body.investigationType, "web_search");
  assert.equal(body.demo, false);
  assert.equal(body.threatAssessment.status, "no_match");
  assert.match(body.summary, /does not mean the website is safe/i);
});

test("Google Safe Browsing matches are returned separately from search evidence", async () => {
  setSearchFetch(async () => jsonResponse({ results: [] }));
  setSafeBrowsingFetch(async () =>
    jsonResponse({
      matches: [
        {
          threatType: "SOCIAL_ENGINEERING",
          threat: { url: "https://example.com/login" }
        },
        {
          threatType: "MALWARE",
          threat: { url: "https://example.com/payload" }
        }
      ]
    })
  );

  const { response, body } = await postInvestigation({
    url: "https://example.com/login"
  });

  assert.equal(response.status, 200);
  assert.equal(body.status, "no_results");
  assert.deepEqual(body.evidence, []);
  assert.equal(body.threatAssessment.status, "reported");
  assert.equal(body.threatAssessment.providers[0].status, "reported");
  assert.deepEqual(body.threatAssessment.providers[0].matches, [
    { threatType: "SOCIAL_ENGINEERING", matchedUrl: "https://example.com/login" },
    { threatType: "MALWARE", matchedUrl: "https://example.com/payload" }
  ]);
});

test("URL heuristic findings remain separate from Safe Browsing statuses", async () => {
  setSearchFetch(async () => jsonResponse({ results: [] }));
  const submittedUrl =
    "https://user:never-return-this@192.0.2.99/private?token=also-never-return-this";

  setSafeBrowsingFetch(async () =>
    jsonResponse({
      matches: [
        {
          threatType: "MALWARE",
          threat: { url: "https://192.0.2.99/private" }
        }
      ]
    })
  );
  const reported = await postInvestigation({ url: submittedUrl });
  assert.equal(reported.body.threatAssessment.status, "reported");
  assert.equal(reported.body.urlSignals.findings[0].ruleId, "ip_address_hostname");

  setSafeBrowsingFetch(async () => jsonResponse({}));
  const noMatch = await postInvestigation({ url: submittedUrl });
  assert.equal(noMatch.body.threatAssessment.status, "no_match");
  assert.equal(noMatch.body.urlSignals.findings[0].ruleId, "ip_address_hostname");

  setSafeBrowsingFetch(async () => {
    throw new Error("mock provider unavailable");
  });
  const unavailable = await postInvestigation({ url: submittedUrl });
  assert.equal(unavailable.body.threatAssessment.status, "unavailable");
  assert.equal(unavailable.body.urlSignals.findings[0].ruleId, "ip_address_hostname");

  for (const result of [reported, noMatch, unavailable]) {
    assert.equal(result.body.status, "no_results");
    assert.ok(!JSON.stringify(result.body).includes("never-return-this"));
    assert.ok(!JSON.stringify(result.body).includes("also-never-return-this"));
  }
});

test("Google Safe Browsing positive results are cached for the returned duration", async () => {
  setSearchFetch(async () => jsonResponse({ results: [] }));
  let safeBrowsingCalls = 0;
  setSafeBrowsingFetch(async () => {
    safeBrowsingCalls += 1;
    return jsonResponse({
      matches: [
        {
          threatType: "MALWARE",
          threat: { url: "https://cache-check.example/path" },
          cacheDuration: "300.000s"
        }
      ]
    });
  });

  const first = await postInvestigation({ url: "https://cache-check.example/path" });
  const second = await postInvestigation({ url: "https://cache-check.example/path" });

  assert.equal(first.response.status, 200);
  assert.equal(second.response.status, 200);
  assert.equal(first.body.threatAssessment.status, "reported");
  assert.equal(second.body.threatAssessment.status, "reported");
  assert.equal(safeBrowsingCalls, 1);
});

test("Google Safe Browsing no-match response is not described as safe", async () => {
  setSearchFetch(async () => jsonResponse({ results: [] }));
  setSafeBrowsingFetch(async () => jsonResponse({}));

  const { response, body } = await postInvestigation({
    url: "https://example.com"
  });

  assert.equal(response.status, 200);
  assert.equal(body.threatAssessment.status, "no_match");
  assert.doesNotMatch(JSON.stringify(body.threatAssessment), /website is safe|clean/i);
  assert.deepEqual(body.urlSignals, { findings: [] });
});

test("missing Google Safe Browsing key returns unavailable without calling provider", async () => {
  delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  setSearchFetch(async () => jsonResponse({ results: [] }));

  let called = false;
  setSafeBrowsingFetch(async () => {
    called = true;
    return jsonResponse({});
  });

  const { response, body } = await postInvestigation({
    url: "https://example.com"
  });

  assert.equal(response.status, 200);
  assert.equal(body.status, "no_results");
  assert.equal(body.threatAssessment.status, "unavailable");
  assert.equal(body.threatAssessment.providers[0].reason, "config_missing");
  assert.equal(called, false);
});

test("Google Safe Browsing HTTP rejection is diagnosed without erasing TinyFish evidence", async () => {
  setSearchFetch(async () =>
    jsonResponse({ results: [{ title: "Search source", url: "https://news.example/source" }] })
  );
  setSafeBrowsingFetch(async () =>
    jsonResponse({ error: `private upstream detail ${TEST_SAFE_BROWSING_KEY}` }, 503)
  );

  const { response, body } = await postInvestigation({
    url: "https://example.com"
  });

  assert.equal(response.status, 200);
  assert.equal(body.status, "research_available");
  assert.equal(body.evidence.length, 1);
  assert.equal(body.threatAssessment.status, "unavailable");
  assert.equal(body.threatAssessment.providers[0].reason, "http_rejection");
  assert.equal(body.threatAssessment.providers[0].httpStatus, 503);
  assert.ok(!JSON.stringify(body).includes(TEST_SAFE_BROWSING_KEY));
  assert.ok(!JSON.stringify(body).includes("private upstream detail"));
  assert.ok(!capturedLogs.join("\n").includes(TEST_SAFE_BROWSING_KEY));
  assert.ok(!capturedLogs.join("\n").includes("private upstream detail"));
  assert.ok(capturedLogs.some((entry) => entry.includes("category=http_rejection, httpStatus=503")));
  assert.ok(!capturedLogs.join("\n").includes("https://example.com"));
});

test("Google Safe Browsing 403 diagnostics include sanitized Google error fields", async () => {
  const submittedUrl = "https://example.com/private/path?session=private-session-value";
  setSearchFetch(async () =>
    jsonResponse({ results: [{ title: "Search source", url: "https://news.example/source" }] })
  );
  setSafeBrowsingFetch(async () =>
    jsonResponse(
      {
        error: {
          code: 403,
          message:
            `Requests for ${submittedUrl} with key=${TEST_SAFE_BROWSING_KEY} were denied.`,
          status: "PERMISSION_DENIED",
          details: [
            {
              reason: "API_KEY_SERVICE_BLOCKED",
              metadata: { privateValue: "must-not-be-logged" }
            }
          ]
        }
      },
      403
    )
  );

  const { response, body } = await postInvestigation({ url: submittedUrl });
  const logs = capturedLogs.join("\n");

  assert.equal(response.status, 200);
  assert.equal(body.threatAssessment.status, "unavailable");
  assert.equal(body.threatAssessment.providers[0].reason, "http_rejection");
  assert.equal(body.threatAssessment.providers[0].httpStatus, 403);
  assert.ok(logs.includes("httpStatus=403"));
  assert.ok(logs.includes("googleCode=403"));
  assert.ok(logs.includes("googleStatus=PERMISSION_DENIED"));
  assert.ok(logs.includes("reasons=API_KEY_SERVICE_BLOCKED"));
  assert.ok(logs.includes("Requests for [redacted-url] with key=[redacted] were denied."));
  assert.ok(!logs.includes(TEST_SAFE_BROWSING_KEY));
  assert.ok(!logs.includes("/private/path"));
  assert.ok(!logs.includes("session=private-session-value"));
  assert.ok(!logs.includes("must-not-be-logged"));
  assert.ok(!JSON.stringify(body).includes("PERMISSION_DENIED"));
  assert.ok(!JSON.stringify(body).includes("API_KEY_SERVICE_BLOCKED"));
});

test("Google Safe Browsing timeouts are unavailable, not clean", async () => {
  process.env.GOOGLE_SAFE_BROWSING_TIMEOUT_MS = "20";
  setSearchFetch(async () => jsonResponse({ results: [] }));
  setSafeBrowsingFetch(
    (url, init) =>
      new Promise((resolve, reject) => {
        init.signal.addEventListener("abort", () => {
          reject(new Error("request aborted"));
        });
      })
  );

  const { response, body } = await postInvestigation({
    url: "https://example.com"
  });

  assert.equal(response.status, 200);
  assert.equal(body.threatAssessment.status, "unavailable");
  assert.equal(body.threatAssessment.providers[0].reason, "timeout");
  assert.ok(capturedLogs.some((entry) => entry.includes("category=timeout")));
});

test("Google Safe Browsing timeout covers response parsing", async () => {
  process.env.GOOGLE_SAFE_BROWSING_TIMEOUT_MS = "20";
  setSearchFetch(async () => jsonResponse({ results: [] }));
  setSafeBrowsingFetch(async () => ({
    ok: true,
    status: 200,
    json: () => new Promise(() => {})
  }));

  const { response, body } = await postInvestigation({
    url: "https://example.com"
  });

  assert.equal(response.status, 200);
  assert.equal(body.threatAssessment.status, "unavailable");
  assert.equal(body.threatAssessment.providers[0].reason, "timeout");
  assert.ok(capturedLogs.some((entry) => entry.includes("category=timeout, httpStatus=200")));
});

test("Google Safe Browsing network failures are unavailable", async () => {
  setSearchFetch(async () => jsonResponse({ results: [] }));
  setSafeBrowsingFetch(async () => {
    throw new Error(`network detail ${TEST_SAFE_BROWSING_KEY}`);
  });

  const { response, body } = await postInvestigation({
    url: "https://example.com"
  });

  assert.equal(response.status, 200);
  assert.equal(body.threatAssessment.status, "unavailable");
  assert.equal(body.threatAssessment.providers[0].reason, "network");
  assert.ok(!JSON.stringify(body).includes(TEST_SAFE_BROWSING_KEY));
  assert.ok(!capturedLogs.join("\n").includes(TEST_SAFE_BROWSING_KEY));
});

test("Google Safe Browsing missing configuration is logged as a safe category", async () => {
  delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  setSearchFetch(async () => jsonResponse({ results: [] }));

  const { response, body } = await postInvestigation({
    url: "https://example.com/private/path?token=not-for-logs"
  });

  assert.equal(response.status, 200);
  assert.equal(body.threatAssessment.status, "unavailable");
  assert.equal(body.threatAssessment.providers[0].reason, "config_missing");
  assert.ok(capturedLogs.some((entry) => entry.includes("category=config_missing")));
  assert.ok(!capturedLogs.join("\n").includes("private/path"));
  assert.ok(!capturedLogs.join("\n").includes("token=not-for-logs"));
});

test("malformed Google Safe Browsing responses are unavailable, not clean", async (t) => {
  const cases = [
    { name: "malformed JSON", response: { ok: true, status: 200, json: async () => { throw new Error("sensitive detail"); } } },
    { name: "matches is not an array", response: jsonResponse({ matches: "invalid" }) },
    {
      name: "match has unsupported shape",
      response: jsonResponse({
        matches: [{ threatType: "UNKNOWN", threat: { url: "https://example.com" } }]
      })
    }
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      setSearchFetch(async () => jsonResponse({ results: [] }));
      setSafeBrowsingFetch(async () => testCase.response);

      const { response, body } = await postInvestigation({
        url: "https://example.com"
      });

      assert.equal(response.status, 200);
      assert.equal(body.threatAssessment.status, "unavailable");
      assert.equal(body.threatAssessment.providers[0].reason, "bad_response");
      assert.ok(!JSON.stringify(body).includes("sensitive detail"));
      assert.ok(capturedLogs.some((entry) => entry.includes("category=bad_response, httpStatus=200")));
    });
  }
});

test("missing, null, and non-array results are malformed upstream responses", async (t) => {
  const cases = [
    { name: "missing results", payload: {} },
    { name: "null results", payload: { results: null } },
    { name: "non-array results", payload: { results: "invalid" } }
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      setSearchFetch(async () =>
        jsonResponse({
          ...testCase.payload,
          sensitiveDetail: TEST_API_KEY
        })
      );

      const { response, body } = await postInvestigation({
        url: "https://example.com"
      });

      assert.equal(response.status, 502);
      assert.match(body.error, /unexpected response/i);
      assert.ok(!JSON.stringify(body).includes(TEST_API_KEY));
      assert.ok(!capturedLogs.join("\n").includes(TEST_API_KEY));
    });
  }
});

test("missing API key returns a clear configuration error without calling TinyFish", async () => {
  delete process.env.TINYFISH_API_KEY;

  let called = false;
  setSearchFetch(async () => {
    called = true;
    return jsonResponse({ results: [] });
  });

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 503);
  assert.match(body.error, /TINYFISH_API_KEY/);
  assert.match(body.error, /configuration/i);
  assert.equal(called, false);
  assert.ok(!JSON.stringify(body).includes(TEST_API_KEY));
  assert.ok(capturedLogs.join("\n").includes("config_missing"));
  assert.ok(!capturedLogs.join("\n").includes(TEST_API_KEY));
});

test("upstream HTTP errors are mapped to a generic 502 response", async () => {
  setSearchFetch(async () =>
    jsonResponse({ error: "internal upstream detail" }, 500)
  );

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 502);
  assert.match(body.error, /unavailable/i);
  assert.ok(!JSON.stringify(body).includes("internal upstream detail"));

  const logged = capturedLogs.join("\n");
  assert.ok(logged.includes("upstreamStatus=500"));
  assert.ok(!logged.includes(TEST_API_KEY));
});

test("upstream rate limits are mapped to a generic busy response", async () => {
  setSearchFetch(async () =>
    jsonResponse({ message: `quota exceeded for key ${TEST_API_KEY}` }, 429)
  );

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 503);
  assert.match(body.error, /busy/i);

  const combined = JSON.stringify(body) + capturedLogs.join("\n");
  assert.ok(!combined.includes(TEST_API_KEY));
  assert.ok(!combined.includes("quota exceeded"));
});

test("malformed JSON from TinyFish maps to a generic 502 response", async () => {
  setSearchFetch(async () => ({
    ok: true,
    status: 200,
    json: async () => {
      throw new SyntaxError("Unexpected token < in JSON");
    }
  }));

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 502);
  assert.match(body.error, /unexpected response/i);
  assert.ok(!JSON.stringify(body).includes("Unexpected token"));
});

test("malformed response shapes map to a generic 502 response", async (t) => {
  const cases = [
    { name: "results is not an array", payload: { results: "not-an-array" } },
    { name: "payload is null", payload: null },
    { name: "payload is an array", payload: [{ title: "x" }] }
  ];

  for (const testCase of cases) {
    await t.test(testCase.name, async () => {
      setSearchFetch(async () => jsonResponse(testCase.payload));

      const { response, body } = await postInvestigation({ url: "https://example.com" });

      assert.equal(response.status, 502);
      assert.match(body.error, /unexpected response/i);
    });
  }
});

test("search timeouts map to a gateway timeout response", async () => {
  process.env.TINYFISH_TIMEOUT_MS = "50";

  setSearchFetch(
    (url, init) =>
      new Promise((resolve, reject) => {
        init.signal.addEventListener("abort", () => {
          const error = new Error("This operation was aborted");
          error.name = "AbortError";
          reject(error);
        });
      })
  );

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 504);
  assert.match(body.error, /timed out/i);
  assert.ok(!capturedLogs.join("\n").includes(TEST_API_KEY));
});

test("network failures map to a generic 502 response", async () => {
  setSearchFetch(async () => {
    const error = new Error("connect ECONNREFUSED 127.0.0.1:1");
    error.cause = { code: "ECONNREFUSED" };
    throw error;
  });

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 502);
  assert.match(body.error, /unreachable/i);
  assert.ok(!JSON.stringify(body).includes("ECONNREFUSED"));
});

test("the API key never appears in responses or logged output", async () => {
  const successCalls = [];
  setSearchFetch(async (url, init) => {
    successCalls.push({ url, init });
    return jsonResponse({
      results: [{ title: "Source", url: "https://source.example/report" }]
    });
  });

  const success = await postInvestigation({ url: "https://example.com" });
  assert.equal(success.response.status, 200);

  setSearchFetch(async () =>
    jsonResponse({ leaked: TEST_API_KEY, message: TEST_API_KEY }, 500)
  );
  const failure = await postInvestigation({ url: "https://example.com" });
  assert.equal(failure.response.status, 502);

  const combined =
    JSON.stringify(success.body) +
    JSON.stringify(failure.body) +
    capturedLogs.join("\n");

  assert.ok(!combined.includes(TEST_API_KEY));

  assert.equal(successCalls.length, 1);
  assert.equal(successCalls[0].init.headers["X-API-Key"], TEST_API_KEY);
  assert.ok(!successCalls[0].url.includes(TEST_API_KEY));
});

test("results are deduplicated without merging distinct URLs", async () => {
  setSearchFetch(async () =>
    jsonResponse({
      results: [
        { title: "First", url: "https://shop.example.com/page?utm_source=x&utm_medium=y" },
        { title: "Duplicate casing", url: "HTTPS://SHOP.EXAMPLE.COM/page" },
        { title: "Duplicate slash", url: "https://shop.example.com/page/" },
        { title: "Sorted params", url: "https://shop.example.com/page?b=2&a=1" },
        { title: "Duplicate param order", url: "https://shop.example.com/page?a=1&b=2" },
        { title: "Fragment variant", url: "https://shop.example.com/page#section" },
        { title: "Distinct scheme", url: "http://shop.example.com/page" },
        { title: "Distinct path", url: "https://shop.example.com/other" },
        { title: "No link", snippet: "kept" },
        { title: "No link", snippet: "kept" }
      ]
    })
  );

  const { response, body } = await postInvestigation({
    url: "https://shop.example.com"
  });

  assert.equal(response.status, 200);
  assert.deepEqual(
    body.evidence.map((entry) => entry.title),
    [
      "First",
      "Duplicate slash",
      "Sorted params",
      "Duplicate param order",
      "Fragment variant",
      "Distinct scheme",
      "Distinct path",
      "No link",
      "No link"
    ]
  );
});

test("parent and sibling domains are not treated as the investigated subdomain", async () => {
  setSearchFetch(async () =>
    jsonResponse({
      results: [
        { title: "Parent site", url: "https://example.com/home", snippet: "Example parent site" },
        { title: "Sibling host", url: "https://sibling.example.com/x", snippet: "Sibling page" },
        { title: "Child host", url: "https://login.shop.example.com/", snippet: "Child page" },
        { title: "Exact host", url: "https://shop.example.com/deals", snippet: "Deals page" }
      ]
    })
  );

  const { response, body } = await postInvestigation({
    url: "https://shop.example.com"
  });

  assert.equal(response.status, 200);
  const byTitle = Object.fromEntries(body.evidence.map((e) => [e.title, e]));

  assert.equal(byTitle["Parent site"].category, "irrelevant_or_unclear");
  assert.equal(
    byTitle["Parent site"].categoryReason,
    "Refers to the parent domain rather than the investigated hostname."
  );
  assert.equal(byTitle["Sibling host"].category, "irrelevant_or_unclear");
  assert.equal(byTitle["Child host"].category, "domain_specific");
  assert.match(byTitle["Child host"].categoryReason, /subdomain of the investigated hostname/i);
  assert.equal(byTitle["Exact host"].category, "domain_specific");
  assert.match(byTitle["Exact host"].categoryReason, /on the investigated hostname/i);
});

test("passing hostname mentions are not classified as domain-specific", async () => {
  setSearchFetch(async () =>
    jsonResponse({
      results: [
        {
          title: "Weekly crypto roundup mentioning shop.example.com among 20 sites",
          url: "https://news.example.org/roundup"
        },
        {
          title: "Shop.example.com review: is it a scam or legitimate store?",
          url: "https://reviews.example.net/shop"
        }
      ]
    })
  );

  const { response, body } = await postInvestigation({
    url: "https://shop.example.com"
  });

  assert.equal(response.status, 200);
  const byTitle = Object.fromEntries(body.evidence.map((e) => [e.title, e]));

  const passing = byTitle[
    "Weekly crypto roundup mentioning shop.example.com among 20 sites"
  ];
  assert.equal(passing.category, "irrelevant_or_unclear");
  assert.match(passing.categoryReason, /passing mention/i);

  const focused = byTitle[
    "Shop.example.com review: is it a scam or legitimate store?"
  ];
  assert.equal(focused.category, "domain_specific");
  assert.match(focused.categoryReason, /does not establish maliciousness/i);

  assert.match(body.summary, /Relevance is not proof of malicious activity/i);
  assert.ok(!JSON.stringify(body).includes(TEST_API_KEY));
});

test("summary describes evidence hosted on the investigated domain as relevant", async () => {
  setSearchFetch(async () =>
    jsonResponse({
      results: [
        {
          title: "Welcome",
          url: "https://example.com/about",
          snippet: "A page with no hostname mention in its text."
        }
      ]
    })
  );

  const { response, body } = await postInvestigation({
    url: "https://example.com"
  });

  assert.equal(response.status, 200);
  assert.match(body.summary, /1 source related to example\.com/i);
  assert.match(body.summary, /Relevance is not proof of malicious activity/i);
  assert.doesNotMatch(body.summary, /explicitly mentions/i);
});

test("zero domain-specific results produce an explicit no-domain-evidence summary", async () => {
  setSearchFetch(async () =>
    jsonResponse({
      results: [
        { title: "How to spot phishing", url: "https://guides.example.org/phishing" },
        { title: "Cat food reviews", url: "https://pets.example.org/cats" }
      ]
    })
  );

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 200);
  assert.equal(body.status, "research_available");
  assert.equal(
    body.evidence.filter((e) => e.category === "domain_specific").length,
    0
  );
  assert.match(body.summary, /No domain-specific sources about example\.com were found/i);
  assert.match(body.summary, /does not mean the website is safe/i);
});

test("upstream 503 responses map to a generic 502 response", async () => {
  setSearchFetch(async () =>
    jsonResponse({ error: "upstream maintenance" }, 503)
  );

  const { response, body } = await postInvestigation({ url: "https://example.com" });

  assert.equal(response.status, 502);
  assert.match(body.error, /unavailable/i);
  assert.ok(!JSON.stringify(body).includes("upstream maintenance"));
  assert.ok(!capturedLogs.join("\n").includes(TEST_API_KEY));
});
