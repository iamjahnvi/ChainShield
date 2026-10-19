const assert = require("node:assert/strict");
const { after, afterEach, before, beforeEach, test } = require("node:test");
const app = require("../src/app");
const {
  TINYFISH_SEARCH_ENDPOINT,
  setSearchFetch
} = require("../src/tinyfish");

const TEST_API_KEY = "unit-test-secret-key-must-never-leak";

const originalConsoleError = console.error;
const originalApiKey = process.env.TINYFISH_API_KEY;
const originalTimeoutMs = process.env.TINYFISH_TIMEOUT_MS;

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
  process.env.TINYFISH_API_KEY = originalApiKey;
  process.env.TINYFISH_TIMEOUT_MS = originalTimeoutMs;
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

beforeEach(() => {
  process.env.TINYFISH_API_KEY = TEST_API_KEY;
  delete process.env.TINYFISH_TIMEOUT_MS;
  capturedLogs = [];
  console.error = (...args) => {
    capturedLogs.push(args.map(String).join(" "));
  };
});

afterEach(() => {
  console.error = originalConsoleError;
  guardFetch();
});

test("valid investigation request returns validated TinyFish results", async () => {
  let captured;
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

  const { response, body } = await postInvestigation({
    url: "https://www.example.com/path?q=demo"
  });

  assert.equal(response.status, 200);
  assert.equal(body.status, "research_available");
  assert.equal(body.domain, "www.example.com");
  assert.equal(body.investigationType, "web_search");
  assert.equal(body.demo, false);
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

  assert.ok(!JSON.stringify(body).includes(TEST_API_KEY));
  assert.equal(capturedLogs.length, 0);
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
  assert.match(body.summary, /does not mean the website is safe/i);
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
