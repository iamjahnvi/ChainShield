const { validateContractAddress } = require("./ethereum-rpc");

const ETHERSCAN_ENDPOINT = "https://api.etherscan.io/v2/api";
const ETHERSCAN_CHAIN_ID = "1";
const DEFAULT_TIMEOUT_MS = 6000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

class EtherscanError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "EtherscanError";
    this.code = code;
  }
}

const defaultFetch = (...args) => globalThis.fetch(...args);
let activeFetch = defaultFetch;

function setEtherscanFetch(fetchImpl) {
  activeFetch = typeof fetchImpl === "function" ? fetchImpl : defaultFetch;
}

function getApiKey(env = process.env) {
  const key = env.ETHERSCAN_API_KEY;
  if (typeof key !== "string" || key.trim() === "") {
    throw new EtherscanError("config_missing", "Etherscan is not configured.");
  }
  return key.trim();
}

function getTimeoutMs(env = process.env) {
  const value = Number(env.ETHERSCAN_TIMEOUT_MS);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_TIMEOUT_MS;
}

async function readBoundedText(response, maxResponseBytes) {
  const contentLength = Number(response.headers?.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maxResponseBytes) {
    throw new EtherscanError("response_too_large", "Etherscan response exceeded the size limit.");
  }

  if (!response.body || typeof response.body.getReader !== "function") {
    throw new EtherscanError("bad_response", "Etherscan returned an unreadable response.");
  }

  const reader = response.body.getReader();
  const chunks = [];
  let byteLength = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      byteLength += value.byteLength;
      if (byteLength > maxResponseBytes) {
        await reader.cancel();
        throw new EtherscanError("response_too_large", "Etherscan response exceeded the size limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function classifyApiFailure(payload) {
  const result =
    typeof payload.result === "string" ? payload.result.toLowerCase() : "";
  const message =
    typeof payload.message === "string" ? payload.message.toLowerCase() : "";
  if (/rate limit|too many requests/.test(`${message} ${result}`)) {
    throw new EtherscanError("rate_limited", "Etherscan rate limit reached.");
  }
  throw new EtherscanError("api_error", "Etherscan could not complete the source lookup.");
}

function parseSourceRecord(payload) {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    !["0", "1"].includes(payload.status) ||
    typeof payload.message !== "string"
  ) {
    throw new EtherscanError("bad_response", "Etherscan returned a malformed response.");
  }

  if (payload.status === "0") {
    const result =
      typeof payload.result === "string" ? payload.result.toLowerCase() : "";
    if (/not verified|no source code/.test(result)) {
      return { verified: false };
    }
    return classifyApiFailure(payload);
  }

  if (!Array.isArray(payload.result) || payload.result.length !== 1) {
    throw new EtherscanError("bad_response", "Etherscan returned an invalid source result.");
  }

  const record = payload.result[0];
  if (
    !record ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    typeof record.SourceCode !== "string" ||
    typeof record.Proxy !== "string" ||
    typeof record.Implementation !== "string"
  ) {
    throw new EtherscanError("bad_response", "Etherscan returned an invalid source record.");
  }

  if (record.SourceCode.trim() === "") {
    return { verified: false };
  }

  const isProxy = record.Proxy === "1" || record.Proxy === "2";
  const implementationAddress =
    record.Implementation.trim() === "" ? null : record.Implementation.trim();
  if (implementationAddress && !validateContractAddress(implementationAddress)) {
    throw new EtherscanError("bad_response", "Etherscan returned an invalid implementation address.");
  }

  return {
    verified: true,
    source: record.SourceCode,
    contractName:
      typeof record.ContractName === "string" ? record.ContractName.slice(0, 120) : "",
    proxy: isProxy || implementationAddress !== null,
    implementationAddress
  };
}

async function getVerifiedSource(address, options = {}) {
  if (!validateContractAddress(address)) {
    throw new EtherscanError("invalid_address", "A 20-byte hexadecimal contract address is required.");
  }

  const env = options.env || process.env;
  const apiKey = getApiKey(env);
  const fetchImpl = options.fetchImpl || activeFetch;
  const timeoutMs = options.timeoutMs || getTimeoutMs(env);
  const maxResponseBytes = options.maxResponseBytes || DEFAULT_MAX_RESPONSE_BYTES;
  const endpoint = new URL(ETHERSCAN_ENDPOINT);
  endpoint.searchParams.set("chainid", ETHERSCAN_CHAIN_ID);
  endpoint.searchParams.set("module", "contract");
  endpoint.searchParams.set("action", "getsourcecode");
  endpoint.searchParams.set("address", address);
  endpoint.searchParams.set("apikey", apiKey);

  const controller = new AbortController();
  let timer;
  const requestPromise = (async () => {
    let response;
    try {
      response = await fetchImpl(endpoint.toString(), {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
        redirect: "error"
      });
    } catch {
      throw new EtherscanError(
        controller.signal.aborted ? "timeout" : "network",
        controller.signal.aborted
          ? "Etherscan source lookup timed out."
          : "Etherscan source lookup failed."
      );
    }

    if (!response || typeof response.ok !== "boolean") {
      throw new EtherscanError("bad_response", "Etherscan returned an unreadable response.");
    }
    if (response.status === 429) {
      throw new EtherscanError("rate_limited", "Etherscan rate limit reached.");
    }
    if (!response.ok) {
      throw new EtherscanError("http_rejection", "Etherscan rejected the source lookup.");
    }

    let text;
    try {
      text = await readBoundedText(response, maxResponseBytes);
    } catch (error) {
      if (error instanceof EtherscanError) {
        throw error;
      }
      throw new EtherscanError("bad_response", "Etherscan returned an unreadable response.");
    }

    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new EtherscanError("bad_response", "Etherscan returned malformed JSON.");
    }
    return parseSourceRecord(payload);
  })();

  const timeoutPromise = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new EtherscanError("timeout", "Etherscan source lookup timed out."));
    }, timeoutMs);
  });

  try {
    return await Promise.race([requestPromise, timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

function sourceFiles(source) {
  let value = source.trim();
  if (value.startsWith("{{") && value.endsWith("}}")) {
    value = value.slice(1, -1);
  }

  if (value.startsWith("{")) {
    try {
      const parsed = JSON.parse(value);
      if (parsed && parsed.sources && typeof parsed.sources === "object") {
        return Object.values(parsed.sources)
          .filter((file) => file && typeof file.content === "string")
          .map((file) => file.content);
      }
    } catch {
      return null;
    }
  }
  return [source];
}

function stripComments(source) {
  let output = "";
  let index = 0;
  let quote = "";
  while (index < source.length) {
    const char = source[index];
    const next = source[index + 1];
    if (quote) {
      output += char === "\n" ? "\n" : " ";
      if (char === "\\" && index + 1 < source.length) {
        output += source[index + 1] === "\n" ? "\n" : " ";
        index += 2;
        continue;
      }
      if (char === quote) {
        quote = "";
      }
      index += 1;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      output += " ";
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      while (index < source.length && source[index] !== "\n") {
        index += 1;
      }
      output += "\n";
      continue;
    }
    if (char === "/" && next === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        if (source[index] === "\n") {
          output += "\n";
        }
        index += 1;
      }
      index = Math.min(source.length, index + 2);
      continue;
    }
    output += char;
    index += 1;
  }
  return output;
}

function sourceLines(source) {
  const files = sourceFiles(source);
  if (!files || files.length === 0) {
    return null;
  }
  return files
    .flatMap((file) => stripComments(file).split(/\r?\n/))
    .filter((line) => line.trim() !== "")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

function matchingEvidence(lines, pattern) {
  const matchingLines = [...new Set(lines.filter((line) => pattern.test(line)))];
  if (matchingLines.length > 0) {
    return matchingLines
      .slice(0, 3)
      .map((line) => (line.length > 180 ? `${line.slice(0, 177)}...` : line));
  }

  const source = lines.join("\n");
  const matchIndex = source.search(pattern);
  if (matchIndex < 0) {
    return [];
  }
  const lineIndex = source.slice(0, matchIndex).split("\n").length - 1;
  const context = lines.slice(Math.max(0, lineIndex - 1), lineIndex + 3).join(" ");
  return [context.length > 180 ? `${context.slice(0, 177)}...` : context];
}

function capability(name, status, evidence, explanation, limitation) {
  return { name, status, evidence, explanation, limitation };
}

function unknownCapabilities() {
  return [
    capability(
      "Privileged minting",
      "unknown",
      [],
      "The source format prevented reliable analysis of mint-related behavior.",
      "No conclusion about minting or authorization can be drawn from source that could not be parsed."
    ),
    capability(
      "Pause controls",
      "unknown",
      [],
      "The source format prevented reliable analysis of pause-related behavior.",
      "No conclusion about pause controls or who can use them can be drawn."
    ),
    capability(
      "Blacklist or denylist controls",
      "unknown",
      [],
      "The source format prevented reliable analysis of address restrictions.",
      "No conclusion about address restriction controls can be drawn."
    ),
    capability(
      "Upgradeability",
      "unknown",
      [],
      "The source format prevented reliable analysis of upgrade mechanisms.",
      "No conclusion about implementation changes or upgrade authorization can be drawn."
    ),
    capability(
      "Privileged administration",
      "unknown",
      [],
      "The source format prevented reliable analysis of administrative controls.",
      "No conclusion about effective access control can be drawn."
    )
  ];
}

function analyzeCapabilities(source, proxyDetected = false) {
  const lines = sourceLines(source);
  if (!lines) {
    return unknownCapabilities();
  }

  const mintEvidence = matchingEvidence(
    lines,
    /\bfunction\s+\w*mint\w*\s*\(|\b_mint\s*\(/
  );
  const pauseEvidence = matchingEvidence(
    lines,
    /\bfunction\s+\w*pause\w*\s*\(|\b_pause\s*\(|\bPausable(?:Upgradeable)?\b/
  );
  const blacklistEvidence = matchingEvidence(
    lines,
    /\bfunction\s+\w*(?:blacklist|denylist|blocklist)\w*\s*\(|\b(?:blacklisted|denylisted|blocklisted)\b/
  );
  const adminEvidence = matchingEvidence(
    lines,
    /\bonlyOwner\b|\bonlyRole\s*\(|\bAccessControl(?:Upgradeable)?\b|\bOwnable(?:Upgradeable)?\b|\bowner\s*\(/
  );
  const upgradeEvidence = matchingEvidence(
    lines,
    /\b(?:upgradeTo|upgradeToAndCall|_authorizeUpgrade)\s*\(|\bUUPSUpgradeable\b|\bTransparentUpgradeableProxy\b|\bERC1967(?:Proxy|Upgrade)\b/
  );
  const upgradeStatus = proxyDetected || upgradeEvidence.length > 0 ? "detected" : "not_detected";
  const operationStatus = (evidence) => {
    if (evidence.length === 0) {
      return "not_detected";
    }
    return evidence.some((line) =>
      /\bonlyOwner\b|\bonlyRole\s*\(|\bhasRole\s*\(|\b_checkRole\s*\(|\brequire\s*\(\s*msg\.sender/i.test(
        line
      )
    )
      ? "detected"
      : "unknown";
  };

  return [
    capability(
      "Privileged minting",
      operationStatus(mintEvidence),
      mintEvidence,
      "Mint-related source may allow creation of additional tokens.",
      "A detected mint operation does not establish who can call it, whether its guard is effective, or whether minting is harmful."
    ),
    capability(
      "Pause controls",
      operationStatus(pauseEvidence),
      pauseEvidence,
      "Pause-related source may allow contract operations or transfers to be suspended.",
      "A detected pause mechanism does not establish who can activate it or whether it can be misused."
    ),
    capability(
      "Blacklist or denylist controls",
      operationStatus(blacklistEvidence),
      blacklistEvidence,
      "Address restriction source may allow selected addresses to be blocked or denied.",
      "A detected restriction mechanism does not establish its reach, conditions, or whether it is harmful."
    ),
    capability(
      "Upgradeability",
      upgradeStatus,
      proxyDetected ? ["Explorer identifies this contract as a proxy."] : upgradeEvidence,
      "Upgrade mechanisms may allow contract logic to be replaced or routed to another implementation.",
      "Source indicators do not establish who controls upgrades or whether an upgrade has occurred."
    ),
    capability(
      "Privileged administration",
      adminEvidence.length > 0 ? "detected" : "not_detected",
      adminEvidence,
      "Ownership or role-related source may define administrative control.",
      "Names and inheritance markers alone do not prove effective access control or identify all authorized accounts."
    )
  ];
}

async function analyzeContractSource(address, chainId, options = {}) {
  if (!validateContractAddress(address)) {
    throw new EtherscanError("invalid_address", "A 20-byte hexadecimal contract address is required.");
  }
  if (typeof chainId !== "string" || !/^0x[0-9a-fA-F]+$/.test(chainId)) {
    return {
      status: "unavailable",
      reason: "rpc_chain_unavailable",
      message: "The Ethereum network could not be confirmed by the RPC check."
    };
  }
  if (BigInt(chainId) !== 1n) {
    return {
      status: "unsupported_chain",
      chainId,
      message: "Verified source analysis currently supports Ethereum Mainnet only."
    };
  }

  const getSource = options.getVerifiedSource || getVerifiedSource;
  let proxyRecord;
  try {
    proxyRecord = await getSource(address, options);
  } catch (error) {
    const reason = error instanceof EtherscanError ? error.code : "provider_error";
    return {
      status: "unavailable",
      chainId,
      reason,
      message: "Verified contract source could not be retrieved."
    };
  }

  if (!proxyRecord.verified) {
    return {
      status: "unverified",
      chainId,
      sourceVerified: false,
      message: "Etherscan does not provide verified source for this address."
    };
  }

  const proxyCapabilities = analyzeCapabilities(proxyRecord.source, proxyRecord.proxy);
  if (proxyCapabilities.some((item) => item.status === "unknown")) {
    return {
      status: "incomplete",
      chainId,
      sourceVerified: true,
      proxy: {
        isProxy: proxyRecord.proxy,
        implementationAddress: proxyRecord.implementationAddress
      },
      proxyAnalysis: { capabilities: proxyCapabilities },
      message: "Verified source was returned in a format the analyzer could not fully parse."
    };
  }

  const response = {
    status: "available",
    chainId,
    network: "Ethereum Mainnet",
    sourceVerified: true,
    contractName: proxyRecord.contractName,
    proxy: {
      isProxy: proxyRecord.proxy,
      implementationAddress: proxyRecord.implementationAddress
    },
    proxyAnalysis: { capabilities: proxyCapabilities }
  };

  if (!proxyRecord.proxy) {
    return response;
  }

  if (!proxyRecord.implementationAddress) {
    return {
      ...response,
      status: "incomplete",
      message: "The contract is identified as a proxy, but no valid implementation address was provided."
    };
  }

  let implementation;
  try {
    implementation = await getSource(proxyRecord.implementationAddress, options);
  } catch {
    return {
      ...response,
      status: "incomplete",
      implementationAnalysis: {
        address: proxyRecord.implementationAddress,
        status: "unavailable"
      },
      message: "Proxy source was analysed, but implementation source could not be retrieved."
    };
  }

  if (!implementation.verified) {
    return {
      ...response,
      status: "incomplete",
      implementationAnalysis: {
        address: proxyRecord.implementationAddress,
        status: "unverified"
      },
      message: "Proxy source was analysed, but implementation source is not verified on Etherscan."
    };
  }

  if (implementation.proxy) {
    return {
      ...response,
      status: "incomplete",
      implementationAnalysis: {
        address: proxyRecord.implementationAddress,
        status: "proxy",
        sourceVerified: true,
        proxy: {
          isProxy: true,
          implementationAddress: implementation.implementationAddress
        }
      },
      message: "The implementation address is itself identified as a proxy. Analysis stopped after one implementation hop."
    };
  }

  const implementationCapabilities = analyzeCapabilities(implementation.source, false);
  if (implementationCapabilities.some((item) => item.status === "unknown")) {
    return {
      ...response,
      status: "incomplete",
      implementationAnalysis: {
        address: proxyRecord.implementationAddress,
        status: "unavailable",
        capabilities: implementationCapabilities
      },
      message: "Proxy source was analysed, but implementation source could not be parsed."
    };
  }

  return {
    ...response,
    implementationAnalysis: {
      address: proxyRecord.implementationAddress,
      status: "available",
      contractName: implementation.contractName,
      capabilities: implementationCapabilities
    }
  };
}

module.exports = {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  ETHERSCAN_CHAIN_ID,
  ETHERSCAN_ENDPOINT,
  EtherscanError,
  analyzeCapabilities,
  analyzeContractSource,
  getVerifiedSource,
  setEtherscanFetch
};
