const { validateContractAddress } = require("./ethereum-rpc");

const ETHERSCAN_ENDPOINT = "https://api.etherscan.io/v2/api";
const ETHERSCAN_CHAIN_ID = "1";
const DEFAULT_TIMEOUT_MS = 6000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_IMPLEMENTATION_HOPS = 3;
const ANALYSIS_REASON_MESSAGES = {
  config_missing: "Etherscan is not configured on the backend.",
  timeout: "The Etherscan source lookup timed out.",
  rate_limited: "Etherscan rate limit was reached.",
  network: "Etherscan could not be reached.",
  http_rejection: "Etherscan rejected the source lookup.",
  api_error: "Etherscan could not complete the source lookup.",
  response_too_large: "Etherscan's response exceeded the configured size limit.",
  bad_response: "Etherscan returned malformed source data.",
  provider_error: "The Etherscan source lookup failed.",
  source_unverified: "An implementation layer is not verified on Etherscan.",
  source_unavailable: "Etherscan could not retrieve source for an implementation layer.",
  malformed_source_response: "Etherscan returned malformed source data for a layer.",
  malformed_proxy_metadata: "Etherscan returned malformed proxy metadata for a layer.",
  missing_implementation_address: "Etherscan marked a layer as a proxy but supplied no implementation address.",
  invalid_implementation_address: "Etherscan supplied an invalid implementation address; it was not requested.",
  cycle_detected: "A repeated implementation address was detected; traversal stopped to avoid a cycle.",
  hop_limit_exceeded: `The implementation chain exceeds the maximum of ${MAX_IMPLEMENTATION_HOPS} implementation hops; remaining layers were not analyzed.`,
  capability_analysis_incomplete: "Verified source was retrieved, but one or more capability indicators could not be classified."
};

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

  const implementationValue = record.Implementation.trim();
  const implementationAddress = validateContractAddress(implementationValue)
    ? implementationValue.toLowerCase()
    : null;
  const isProxy =
    record.Proxy === "1" ||
    record.Proxy === "2" ||
    implementationValue !== "";

  return {
    verified: true,
    source: record.SourceCode,
    contractName:
      typeof record.ContractName === "string" ? record.ContractName.slice(0, 120) : "",
    proxy: isProxy || implementationAddress !== null,
    implementationAddress,
    invalidImplementationAddress:
      implementationValue !== "" && implementationAddress === null,
    invalidProxyMetadata: !["0", "1", "2"].includes(record.Proxy)
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
  const source = lines.join("\n");
  const matcher = new RegExp(pattern.source, `${pattern.flags.replace(/[gy]/g, "")}g`);
  const evidence = [];
  for (const match of source.matchAll(matcher)) {
    const context = source
      .slice(match.index, Math.min(source.length, match.index + match[0].length + 100))
      .replace(/\s+/g, " ")
      .trim();
    const excerpt = context.length > 180 ? `${context.slice(0, 177)}...` : context;
    if (!evidence.includes(excerpt)) {
      evidence.push(excerpt);
    }
    if (evidence.length === 3) {
      break;
    }
  }
  return evidence;
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
  const operationStatus = (evidence) =>
    evidence.length > 0 ? "detected" : "not_detected";

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
  const layers = [];
  const visited = new Set();
  let nextAddress = address.toLowerCase();
  let hops = 0;
  let initialFailure;

  while (nextAddress) {
    const normalizedAddress = nextAddress.toLowerCase();
    if (visited.has(normalizedAddress)) {
      layers.push({
        address: normalizedAddress,
        proxyStatus: "unknown",
        sourceVerified: null,
        status: "cycle",
        reason: "cycle_detected",
        capabilities: []
      });
      break;
    }
    visited.add(normalizedAddress);

    let sourceRecord;
    try {
      sourceRecord = await getSource(normalizedAddress, options);
    } catch (error) {
      const reason = error instanceof EtherscanError ? error.code : "provider_error";
      if (layers.length === 0) {
        initialFailure = reason;
        break;
      }
      layers.push({
        address: normalizedAddress,
        proxyStatus: "unknown",
        sourceVerified: null,
        status: reason === "bad_response" ? "malformed" : "unavailable",
        reason,
        capabilities: []
      });
      break;
    }

    if (
      !sourceRecord ||
      typeof sourceRecord !== "object" ||
      typeof sourceRecord.verified !== "boolean"
    ) {
      if (layers.length === 0) {
        initialFailure = "bad_response";
        break;
      }
      layers.push({
        address: normalizedAddress,
        proxyStatus: "unknown",
        sourceVerified: null,
        status: "malformed",
        reason: "malformed_source_response",
        capabilities: []
      });
      break;
    }

    if (sourceRecord.verified === false) {
      layers.push({
        address: normalizedAddress,
        proxyStatus: "unknown",
        sourceVerified: false,
        status: "unverified",
        reason: "source_unverified",
        capabilities: []
      });
      break;
    }

    if (
      typeof sourceRecord.source !== "string" ||
      typeof sourceRecord.proxy !== "boolean" ||
      (sourceRecord.implementationAddress !== null &&
        sourceRecord.implementationAddress !== undefined &&
        !validateContractAddress(sourceRecord.implementationAddress)) ||
      sourceRecord.invalidProxyMetadata === true ||
      sourceRecord.invalidImplementationAddress === true
    ) {
      const invalidImplementationAddress =
        sourceRecord.invalidImplementationAddress === true ||
        (sourceRecord.implementationAddress !== null &&
          sourceRecord.implementationAddress !== undefined &&
          !validateContractAddress(sourceRecord.implementationAddress));
      layers.push({
        address: normalizedAddress,
        proxyStatus:
          sourceRecord.invalidProxyMetadata === true
            ? "unknown"
            : sourceRecord.proxy === true
              ? "proxy"
              : "unknown",
        sourceVerified: true,
        status: "malformed",
        reason: invalidImplementationAddress
          ? "invalid_implementation_address"
          : "malformed_proxy_metadata",
        implementationAddress: null,
        contractName:
          typeof sourceRecord.contractName === "string"
            ? sourceRecord.contractName.slice(0, 120)
            : "",
        capabilities:
          typeof sourceRecord.source === "string"
            ? analyzeCapabilities(sourceRecord.source, sourceRecord.proxy === true)
            : unknownCapabilities()
      });
      break;
    }

    const capabilities = analyzeCapabilities(
      sourceRecord.source,
      sourceRecord.proxy
    );
    const layer = {
      address: normalizedAddress,
      proxyStatus: sourceRecord.proxy ? "proxy" : "not_proxy",
      sourceVerified: true,
      status: capabilities.some((item) => item.status === "unknown")
        ? "incomplete"
        : "available",
      reason: capabilities.some((item) => item.status === "unknown")
        ? "capability_analysis_incomplete"
        : null,
      contractName: sourceRecord.contractName || "",
      implementationAddress: sourceRecord.implementationAddress || null,
      capabilities
    };
    layers.push(layer);

    if (!sourceRecord.proxy) {
      break;
    }
    if (!sourceRecord.implementationAddress) {
      layer.status = "malformed";
      layer.reason = "missing_implementation_address";
      break;
    }

    const implementationAddress = sourceRecord.implementationAddress.toLowerCase();
    if (!validateContractAddress(implementationAddress)) {
      layer.status = "malformed";
      layer.reason = "invalid_implementation_address";
      break;
    }
    if (visited.has(implementationAddress)) {
      layers.push({
        address: implementationAddress,
        proxyStatus: "unknown",
        sourceVerified: null,
        status: "cycle",
        reason: "cycle_detected",
        capabilities: []
      });
      break;
    }
    if (hops >= MAX_IMPLEMENTATION_HOPS) {
      layers.push({
        address: implementationAddress,
        proxyStatus: "not_checked",
        sourceVerified: null,
        status: "hop_limit",
        reason: "hop_limit_exceeded",
        capabilities: []
      });
      break;
    }

    hops += 1;
    nextAddress = implementationAddress;
  }

  if (initialFailure) {
    return {
      status: initialFailure === "bad_response" ? "incomplete" : "unavailable",
      chainId,
      reason: initialFailure,
      ...(initialFailure === "bad_response"
        ? {
            layers: [
              {
                address: address.toLowerCase(),
                proxyStatus: "unknown",
                sourceVerified: null,
                status: "malformed",
                reason: "malformed_source_response",
                capabilities: []
              }
            ]
          }
        : {}),
      message:
        ANALYSIS_REASON_MESSAGES[initialFailure] ||
        "Verified contract source could not be retrieved."
    };
  }

  const firstLayer = layers[0];
  if (!firstLayer || firstLayer.status === "unverified") {
    return {
      status: "unverified",
      chainId,
      network: "Ethereum Mainnet",
      reason: "source_unverified",
      sourceVerified: false,
      layers,
      message: "Etherscan does not provide verified source for the submitted contract."
    };
  }

  const incompleteLayers = layers.filter((layer) => layer.status !== "available");
  const incompleteLayer = incompleteLayers[incompleteLayers.length - 1];
  const status = incompleteLayer ? "incomplete" : "available";
  const firstImplementation = layers[1];
  const response = {
    status,
    ...(incompleteLayer ? { reason: incompleteLayer.reason } : {}),
    chainId,
    network: "Ethereum Mainnet",
    sourceVerified: firstLayer.sourceVerified === true,
    contractName: firstLayer.contractName || "",
    proxy: {
      isProxy: firstLayer.proxyStatus === "proxy",
      implementationAddress: firstLayer.implementationAddress || null
    },
    proxyAnalysis: { capabilities: firstLayer.capabilities || [] },
    layers,
    ...(firstImplementation
      ? {
          implementationAnalysis: {
            address: firstImplementation.address,
            status: firstImplementation.status,
            sourceVerified: firstImplementation.sourceVerified,
            proxyStatus: firstImplementation.proxyStatus,
            contractName: firstImplementation.contractName || "",
            implementationAddress: firstImplementation.implementationAddress || null,
            capabilities: firstImplementation.capabilities || []
          }
        }
      : {})
  };

  if (incompleteLayer) {
    response.message =
      ANALYSIS_REASON_MESSAGES[incompleteLayer.reason] ||
      "The implementation chain could not be fully analyzed.";
  }
  return response;
}

module.exports = {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  ETHERSCAN_CHAIN_ID,
  ETHERSCAN_ENDPOINT,
  MAX_IMPLEMENTATION_HOPS,
  EtherscanError,
  analyzeCapabilities,
  analyzeContractSource,
  getVerifiedSource,
  setEtherscanFetch
};
