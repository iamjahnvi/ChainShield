const assert = require("node:assert/strict");
const { test } = require("node:test");
const {
  EtherscanError,
  analyzeCapabilities,
  analyzeContractSource,
  getVerifiedSource
} = require("../src/etherscan");

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const IMPLEMENTATION = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const API_KEY = "etherscan-test-key-must-never-leak";
const ENV = { ETHERSCAN_API_KEY: API_KEY };

function apiResponse(record, status = "1", message = "OK") {
  return new Response(
    JSON.stringify({
      status,
      message,
      result: Array.isArray(record) || typeof record === "string" ? record : [record]
    }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

function sourceRecord(source, overrides = {}) {
  return {
    SourceCode: source,
    ContractName: "ExampleToken",
    Proxy: "0",
    Implementation: "",
    ...overrides
  };
}

test("requests verified source from the fixed Etherscan V2 endpoint", async () => {
  let requestUrl;
  let requestOptions;
  const record = sourceRecord("contract Example {}");
  const result = await getVerifiedSource(ADDRESS, {
    env: ENV,
    fetchImpl: async (url, options) => {
      requestUrl = new URL(url);
      requestOptions = options;
      return apiResponse(record);
    }
  });

  assert.equal(requestUrl.origin + requestUrl.pathname, "https://api.etherscan.io/v2/api");
  assert.equal(requestUrl.searchParams.get("chainid"), "1");
  assert.equal(requestUrl.searchParams.get("module"), "contract");
  assert.equal(requestUrl.searchParams.get("action"), "getsourcecode");
  assert.equal(requestUrl.searchParams.get("address"), ADDRESS);
  assert.equal(requestUrl.searchParams.get("apikey"), API_KEY);
  assert.equal(requestOptions.method, "GET");
  assert.equal(requestOptions.redirect, "error");
  assert.equal(result.verified, true);
  assert.equal(result.source, record.SourceCode);
});

test("rejects invalid addresses and missing configuration before fetching", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return apiResponse(sourceRecord("contract Example {}"));
  };
  await assert.rejects(
    getVerifiedSource("0x123", { env: ENV, fetchImpl }),
    (error) => error.code === "invalid_address"
  );
  await assert.rejects(
    getVerifiedSource(ADDRESS, { env: {}, fetchImpl }),
    (error) => error.code === "config_missing"
  );
  assert.equal(calls, 0);
});

test("recognizes an unverified contract response", async () => {
  const result = await getVerifiedSource(ADDRESS, {
    env: ENV,
    fetchImpl: async () =>
      apiResponse("Contract source code not verified", "0", "NOTOK")
  });
  assert.deepEqual(result, { verified: false });
});

test("classifies Etherscan API errors and rate limits without exposing provider text", async (t) => {
  await t.test("API failure", async () => {
    await assert.rejects(
      getVerifiedSource(ADDRESS, {
        env: ENV,
        fetchImpl: async () => apiResponse("private provider detail", "0", "NOTOK")
      }),
      (error) => {
        assert.equal(error.code, "api_error");
        assert.ok(!error.message.includes("private provider detail"));
        assert.ok(!error.stack.includes(API_KEY));
        return true;
      }
    );
  });
  await t.test("rate limit", async () => {
    await assert.rejects(
      getVerifiedSource(ADDRESS, {
        env: ENV,
        fetchImpl: async () => apiResponse("Rate limit reached", "0", "NOTOK")
      }),
      (error) => error.code === "rate_limited"
    );
  });
  await t.test("HTTP 429", async () => {
    await assert.rejects(
      getVerifiedSource(ADDRESS, {
        env: ENV,
        fetchImpl: async () => new Response("", { status: 429 })
      }),
      (error) => error.code === "rate_limited"
    );
  });
});

test("sanitizes network failures and timeouts", async (t) => {
  await t.test("network error", async () => {
    await assert.rejects(
      getVerifiedSource(ADDRESS, {
        env: ENV,
        fetchImpl: async () => {
          throw new Error(`request failed for apikey=${API_KEY}`);
        }
      }),
      (error) => {
        assert.equal(error.code, "network");
        assert.ok(!error.message.includes(API_KEY));
        assert.ok(!error.stack.includes(API_KEY));
        return true;
      }
    );
  });
  await t.test("timeout", async () => {
    await assert.rejects(
      getVerifiedSource(ADDRESS, {
        env: ENV,
        timeoutMs: 10,
        fetchImpl: (_url, options) =>
          new Promise((resolve, reject) => {
            options.signal.addEventListener("abort", () => reject(new Error("aborted")));
          })
      }),
      (error) => error.code === "timeout"
    );
  });
});

test("rejects malformed, oversized, and unsuccessful responses", async (t) => {
  const malformedResponses = [
    ["invalid JSON", () => new Response("{", { status: 200 })],
    ["malformed structure", () => apiResponse([{ SourceCode: "x" }])],
    ["HTTP rejection", () => new Response("", { status: 503 })],
    [
      "oversized response",
      () =>
        new Response("{}", {
          status: 200,
          headers: { "Content-Length": "2048" }
        })
    ],
    [
      "oversized streamed response",
      () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new Uint8Array(2048));
              controller.close();
            }
          }),
          { status: 200 }
        )
    ]
  ];

  for (const [name, responseFactory] of malformedResponses) {
    await t.test(name, async () => {
      await assert.rejects(
        getVerifiedSource(ADDRESS, {
          env: ENV,
          maxResponseBytes: 1024,
          fetchImpl: async () => responseFactory()
        }),
        EtherscanError
      );
    });
  }
});

test("detects potential capabilities in verified source with explicit limitations", () => {
  const source = [
    "contract Token {",
    "  function mint(address to, uint256 amount) external onlyOwner { _mint(to, amount); }",
    "  function pause() external onlyRole(PAUSER_ROLE) { _pause(); }",
    "  mapping(address => bool) public blacklisted;",
    "  function setBlacklist(address user, bool blocked) external onlyOwner { blacklisted[user] = blocked; }",
    "  function upgradeTo(address next) external onlyOwner { }",
    "}"
  ].join("\n");

  const capabilities = analyzeCapabilities(source);
  assert.deepEqual(
    capabilities.map(({ name, status }) => [name, status]),
    [
      ["Privileged minting", "detected"],
      ["Pause controls", "detected"],
      ["Blacklist or denylist controls", "detected"],
      ["Upgradeability", "detected"],
      ["Privileged administration", "detected"]
    ]
  );
  assert.ok(capabilities.every((item) => item.limitation.length > 0));
  assert.ok(capabilities[0].evidence.some((line) => line.includes("function mint")));
});

test("does not infer privileged minting from a function name or unrelated owner guard", () => {
  const capabilities = analyzeCapabilities([
    "contract Token {",
    "  function setFee(uint256 fee) external onlyOwner { }",
    "  function mint(address to, uint256 amount) external { _mint(to, amount); }",
    "}"
  ].join("\n"));
  assert.equal(capabilities[0].status, "unknown");
  assert.equal(capabilities[1].status, "not_detected");
  assert.equal(capabilities[4].status, "detected");
});

test("keeps multiline mint evidence unknown when the access guard is ambiguous", () => {
  const capabilities = analyzeCapabilities([
    "contract Token {",
    "  function",
    "    mint(address to)",
    "    external onlyOwner",
    "  { _mint(to, 1); }",
    "}"
  ].join("\n"));
  assert.equal(capabilities[0].status, "unknown");
  assert.ok(capabilities[0].evidence[0].includes("_mint(to, 1)"));
});

test("ordinary verified source reports no matching indicators without a safety verdict", () => {
  const capabilities = analyzeCapabilities("contract PlainStorage { uint256 public value; }");
  assert.ok(capabilities.every((item) => item.status === "not_detected"));
  assert.ok(capabilities.every((item) => /does not|do not/.test(item.limitation)));
});

test("ignores capability-like text in Solidity comments", () => {
  const capabilities = analyzeCapabilities([
    "contract PlainStorage {",
    "  // function mint(address to) external onlyOwner { }",
    "  /* function pause() external { } */",
    "  uint256 public value;",
    "}"
  ].join("\n"));
  assert.ok(capabilities.every((item) => item.status === "not_detected"));
});

test("ignores capability-like text inside string literals", () => {
  const capabilities = analyzeCapabilities([
    "contract PlainStorage {",
    '  string constant note = "function mint(address to) external onlyOwner";',
    "  uint256 public value;",
    "}"
  ].join("\n"));
  assert.ok(capabilities.every((item) => item.status === "not_detected"));
});

test("returns unknown when source format cannot be parsed", () => {
  const capabilities = analyzeCapabilities('{"sources":{"Token.sol":{"content":true}}}');
  assert.ok(capabilities.every((item) => item.status === "unknown"));
});

test("analyzes a verified ordinary contract on Mainnet", async () => {
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => ({
      verified: true,
      source: "contract PlainStorage { uint256 public value; }",
      contractName: "PlainStorage",
      proxy: false,
      implementationAddress: null
    })
  });

  assert.equal(analysis.status, "available");
  assert.equal(analysis.network, "Ethereum Mainnet");
  assert.equal(analysis.sourceVerified, true);
  assert.equal(analysis.proxy.isProxy, false);
  assert.equal(analysis.proxyAnalysis.capabilities[0].status, "not_detected");
  assert.ok(!JSON.stringify(analysis).includes("contract PlainStorage"));
});

test("does not assume Mainnet when the RPC chain is unavailable or unsupported", async () => {
  assert.equal(
    (await analyzeContractSource(ADDRESS, null, { getVerifiedSource: async () => assert.fail() }))
      .status,
    "unavailable"
  );
  assert.equal(
    (await analyzeContractSource(ADDRESS, "0x89", { getVerifiedSource: async () => assert.fail() }))
      .status,
    "unsupported_chain"
  );
});

test("analyzes proxy and implementation source separately with a single implementation hop", async () => {
  const lookupAddresses = [];
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async (address) => {
      lookupAddresses.push(address);
      if (address === ADDRESS) {
        return {
          verified: true,
          source: "contract Proxy {}",
          contractName: "Proxy",
          proxy: true,
          implementationAddress: IMPLEMENTATION
        };
      }
      return {
        verified: true,
        source: "contract Impl { function pause() external onlyOwner { _pause(); } }",
        contractName: "Impl",
        proxy: false,
        implementationAddress: null
      };
    }
  });

  assert.equal(analysis.status, "available");
  assert.deepEqual(lookupAddresses, [ADDRESS, IMPLEMENTATION]);
  assert.equal(analysis.proxy.isProxy, true);
  assert.equal(analysis.proxyAnalysis.capabilities[3].status, "detected");
  assert.equal(analysis.implementationAnalysis.address, IMPLEMENTATION);
  assert.equal(analysis.implementationAnalysis.capabilities[1].status, "detected");
  assert.equal(analysis.implementationAnalysis.capabilities[3].status, "not_detected");
});

test("marks an unverified proxy implementation as incomplete", async () => {
  let calls = 0;
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => {
      calls += 1;
      return calls === 1
        ? {
            verified: true,
            source: "contract Proxy {}",
            contractName: "Proxy",
            proxy: true,
            implementationAddress: IMPLEMENTATION
          }
        : { verified: false };
    }
  });

  assert.equal(analysis.status, "incomplete");
  assert.equal(analysis.implementationAnalysis.status, "unverified");
});

test("marks an unavailable proxy implementation source as incomplete", async () => {
  let calls = 0;
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => {
      calls += 1;
      if (calls === 1) {
        return {
          verified: true,
          source: "contract Proxy {}",
          contractName: "Proxy",
          proxy: true,
          implementationAddress: IMPLEMENTATION
        };
      }
      throw new EtherscanError("network", "sanitized");
    }
  });
  assert.equal(analysis.status, "incomplete");
  assert.equal(analysis.implementationAnalysis.status, "unavailable");
  assert.equal(calls, 2);
});

test("stops after one hop when the implementation is itself a proxy", async () => {
  let calls = 0;
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => {
      calls += 1;
      return {
        verified: true,
        source: "contract Proxy {}",
        contractName: "Proxy",
        proxy: true,
        implementationAddress: calls === 1 ? IMPLEMENTATION : ADDRESS
      };
    }
  });
  assert.equal(calls, 2);
  assert.equal(analysis.status, "incomplete");
  assert.equal(analysis.implementationAnalysis.status, "proxy");
});

test("returns unverified and unavailable states without exposing provider details", async () => {
  const unverified = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => ({ verified: false })
  });
  assert.equal(unverified.status, "unverified");
  assert.equal(unverified.sourceVerified, false);

  const unavailable = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => {
      throw new Error(`provider failure with key ${API_KEY}`);
    }
  });
  assert.equal(unavailable.status, "unavailable");
  assert.ok(!JSON.stringify(unavailable).includes(API_KEY));
});
