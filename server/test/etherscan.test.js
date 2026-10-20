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
const IMPLEMENTATION_TWO = "0x9876543210abcdef9876543210abcdef98765432";
const IMPLEMENTATION_THREE = "0x1111111111111111111111111111111111111111";
const IMPLEMENTATION_FOUR = "0x2222222222222222222222222222222222222222";
const USDC_PROXY = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const USDC_IMPLEMENTATION = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd";
const USDC_NEXT_IMPLEMENTATION = "0x800c32eaa2a6c93cf4cb51794450ed77fbfbb172";
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

test("retains malformed implementation metadata without treating it as an address", async () => {
  const result = await getVerifiedSource(ADDRESS, {
    env: ENV,
    fetchImpl: async () =>
      apiResponse(
        sourceRecord("contract Proxy {}", {
          Proxy: "1",
          Implementation: "malformed-address-value"
        })
      )
  });
  assert.equal(result.verified, true);
  assert.equal(result.proxy, true);
  assert.equal(result.implementationAddress, null);
  assert.equal(result.invalidImplementationAddress, true);
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

test("reports observed operation patterns without asserting effective privileges", () => {
  const capabilities = analyzeCapabilities([
    "contract Token {",
    "  function setFee(uint256 fee) external onlyOwner { }",
    "  function mint(address to, uint256 amount) external { _mint(to, amount); }",
    "}"
  ].join("\n"));
  assert.equal(capabilities[0].status, "detected");
  assert.match(capabilities[0].limitation, /does not establish who can call it/i);
  assert.equal(capabilities[1].status, "not_detected");
  assert.equal(capabilities[4].status, "detected");
});

test("detects multiline mint, pause, and blacklist patterns and preserves evidence context", () => {
  const capabilities = analyzeCapabilities([
    "contract Token {",
    "  function",
    "    mint(address to) external",
    "    onlyOwner",
    "  { _mint(to, 1); }",
    "  function pause() external",
    "    onlyOwner",
    "  { _pause(); }",
    "  function blacklist(address account) external",
    "    onlyOwner",
    "  { blacklisted[account] = true; }",
    "}"
  ].join("\n"));
  assert.equal(capabilities[0].status, "detected");
  assert.equal(capabilities[1].status, "detected");
  assert.equal(capabilities[2].status, "detected");
  assert.ok(capabilities[0].evidence[0].includes("onlyOwner"));
  assert.match(capabilities[0].limitation, /does not establish who can call it/i);
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

test("analyzes a proxy and its single implementation in separate layers", async () => {
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
  assert.equal(analysis.implementationAnalysis.proxyStatus, "not_proxy");
  assert.equal(analysis.implementationAnalysis.capabilities[1].status, "detected");
  assert.equal(analysis.implementationAnalysis.capabilities[3].status, "not_detected");
  assert.deepEqual(
    analysis.layers.map(({ address, status, proxyStatus, sourceVerified }) => ({
      address,
      status,
      proxyStatus,
      sourceVerified
    })),
    [
      {
        address: ADDRESS,
        status: "available",
        proxyStatus: "proxy",
        sourceVerified: true
      },
      {
        address: IMPLEMENTATION,
        status: "available",
        proxyStatus: "not_proxy",
        sourceVerified: true
      }
    ]
  );
});

test("continues through a proxy implementation even when its source cannot be classified", async () => {
  const chain = [USDC_PROXY, USDC_IMPLEMENTATION, USDC_NEXT_IMPLEMENTATION];
  const calls = [];
  const analysis = await analyzeContractSource(USDC_PROXY, "0x1", {
    getVerifiedSource: async (address) => {
      calls.push(address);
      const index = calls.length - 1;
      return {
        verified: true,
        source:
          index === 1
            ? '{"sources":{"FiatTokenV2_2.sol":{"content":false}}}'
            : `contract Layer${index} {}`,
        contractName: index === 1 ? "FiatTokenV2_2" : `Layer${index}`,
        proxy: index < chain.length - 1,
        implementationAddress: chain[index + 1] || null
      };
    }
  });

  assert.equal(analysis.status, "incomplete");
  assert.equal(analysis.reason, "capability_analysis_incomplete");
  assert.deepEqual(calls, chain);
  assert.equal(analysis.layers.length, 3);
  assert.deepEqual(
    analysis.layers.map((layer) => layer.address),
    chain
  );
  assert.equal(analysis.layers[1].status, "incomplete");
  assert.ok(analysis.layers[1].capabilities.every((capability) => capability.status === "unknown"));
  assert.equal(analysis.layers[2].status, "available");
});

test("reports the later source failure as the chain stopping reason", async () => {
  let calls = 0;
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => {
      calls += 1;
      if (calls === 1) {
        return {
          verified: true,
          source: '{"sources":{"FiatTokenV2_2.sol":{"content":false}}}',
          contractName: "UnparsedProxy",
          proxy: true,
          implementationAddress: IMPLEMENTATION
        };
      }
      throw new EtherscanError("timeout", "sanitized timeout");
    }
  });

  assert.equal(calls, 2);
  assert.equal(analysis.status, "incomplete");
  assert.equal(analysis.reason, "timeout");
  assert.equal(analysis.layers[0].reason, "capability_analysis_incomplete");
  assert.equal(analysis.layers[1].reason, "timeout");
  assert.match(analysis.message, /timed out/i);
});

test("analyzes nested proxy layers through the three-hop limit", async () => {
  const chain = [ADDRESS, IMPLEMENTATION, IMPLEMENTATION_TWO, IMPLEMENTATION_THREE];
  const calls = [];
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async (address) => {
      calls.push(address);
      const index = chain.indexOf(address);
      return {
        verified: true,
        source: `contract Layer${index} { function pause() external onlyOwner { _pause(); } }`,
        contractName: `Layer${index}`,
        proxy: index < chain.length - 1,
        implementationAddress: chain[index + 1] || null
      };
    }
  });

  assert.equal(analysis.status, "available");
  assert.deepEqual(calls, chain);
  assert.equal(analysis.layers.length, 4);
  assert.ok(analysis.layers.every((layer) => layer.sourceVerified === true));
});

test("stops before fetching a fourth implementation hop and marks the chain incomplete", async () => {
  const chain = [
    ADDRESS,
    IMPLEMENTATION,
    IMPLEMENTATION_TWO,
    IMPLEMENTATION_THREE,
    IMPLEMENTATION_FOUR
  ];
  const calls = [];
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async (address) => {
      calls.push(address);
      const index = chain.indexOf(address);
      return {
        verified: true,
        source: `contract Layer${index} {}`,
        contractName: `Layer${index}`,
        proxy: true,
        implementationAddress: chain[index + 1] || null
      };
    }
  });

  assert.equal(analysis.status, "incomplete");
  assert.deepEqual(calls, chain.slice(0, 4));
  assert.equal(analysis.layers.length, 5);
  assert.equal(analysis.layers[4].address, IMPLEMENTATION_FOUR);
  assert.equal(analysis.layers[4].status, "hop_limit");
  assert.equal(analysis.layers[4].reason, "hop_limit_exceeded");
  assert.equal(analysis.layers[4].sourceVerified, null);
  assert.equal(analysis.reason, "hop_limit_exceeded");
  assert.match(analysis.message, /maximum of 3 implementation hops/);
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
  assert.equal(analysis.reason, "source_unverified");
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
  assert.equal(analysis.reason, "network");
  assert.equal(analysis.implementationAnalysis.status, "unavailable");
  assert.equal(calls, 2);
});

test("detects a repeated address cycle after following implementation metadata", async () => {
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
  assert.equal(analysis.reason, "cycle_detected");
  assert.deepEqual(
    analysis.layers.map((layer) => layer.status),
    ["available", "available", "cycle"]
  );
  assert.equal(analysis.layers[2].address, ADDRESS);
  assert.match(analysis.message, /cycle/i);
});

test("marks invalid implementation metadata incomplete without requesting that address", async () => {
  const calls = [];
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async (address) => {
      calls.push(address);
      return {
        verified: true,
        source: "contract Proxy {}",
        contractName: "Proxy",
        proxy: true,
        implementationAddress: "not-an-address"
      };
    }
  });
  assert.equal(analysis.status, "incomplete");
  assert.equal(analysis.reason, "invalid_implementation_address");
  assert.deepEqual(calls, [ADDRESS]);
  assert.equal(analysis.layers[0].status, "malformed");
  assert.equal(analysis.layers[0].implementationAddress, null);
  assert.match(analysis.message, /invalid implementation address/i);
  assert.ok(!JSON.stringify(analysis).includes("not-an-address"));
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

test("marks malformed root source data incomplete", async () => {
  const analysis = await analyzeContractSource(ADDRESS, "0x1", {
    getVerifiedSource: async () => {
      throw new EtherscanError("bad_response", "sanitized malformed response");
    }
  });
  assert.equal(analysis.status, "incomplete");
  assert.equal(analysis.layers[0].address, ADDRESS);
  assert.equal(analysis.layers[0].status, "malformed");
  assert.equal(analysis.layers[0].sourceVerified, null);
  assert.match(analysis.message, /malformed source data/);
});
