const ETHEREUM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const DEFAULT_TIMEOUT_MS = 6000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;

class EthereumRpcError extends Error {
  constructor(code, message, { providerCode } = {}) {
    super(message);
    this.name = "EthereumRpcError";
    this.code = code;
    if (providerCode !== undefined) {
      this.providerCode = providerCode;
    }
  }
}

const defaultFetch = (...args) => globalThis.fetch(...args);
let activeFetch = defaultFetch;

function setEthereumRpcFetch(fetchImpl) {
  activeFetch = typeof fetchImpl === "function" ? fetchImpl : defaultFetch;
}

function validateContractAddress(value) {
  return typeof value === "string" && ETHEREUM_ADDRESS_PATTERN.test(value);
}

function getEndpoint(env = process.env) {
  const endpointValue = env.ETH_RPC_URL;
  if (typeof endpointValue !== "string" || endpointValue.trim() === "") {
    throw new EthereumRpcError("config_missing", "Ethereum RPC is not configured.");
  }

  let endpoint;
  try {
    endpoint = new URL(endpointValue);
  } catch {
    throw new EthereumRpcError("config_invalid", "Ethereum RPC configuration is invalid.");
  }

  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) {
    throw new EthereumRpcError("config_invalid", "Ethereum RPC configuration is invalid.");
  }

  return endpoint.toString();
}

function getTimeoutMs(env = process.env) {
  const value = Number(env.ETH_RPC_TIMEOUT_MS);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_TIMEOUT_MS;
}

async function readBoundedText(response, maxResponseBytes) {
  const declaredLength = Number(response.headers?.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxResponseBytes) {
    throw new EthereumRpcError("response_too_large", "Ethereum RPC response exceeded the size limit.");
  }

  if (!response.body || typeof response.body.getReader !== "function") {
    throw new EthereumRpcError("bad_response", "Ethereum RPC returned an unreadable response.");
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
        throw new EthereumRpcError(
          "response_too_large",
          "Ethereum RPC response exceeded the size limit."
        );
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

function parseRpcResponse(payload, id) {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    payload.jsonrpc !== "2.0" ||
    payload.id !== id
  ) {
    throw new EthereumRpcError("bad_response", "Ethereum RPC returned a malformed response.");
  }

  if (
    payload.error &&
    typeof payload.error === "object" &&
    !Array.isArray(payload.error) &&
    Number.isInteger(payload.error.code)
  ) {
    throw new EthereumRpcError("rpc_error", "Ethereum RPC reported an error.", {
      providerCode: payload.error.code
    });
  }

  if (!Object.prototype.hasOwnProperty.call(payload, "result")) {
    throw new EthereumRpcError("bad_response", "Ethereum RPC response omitted its result.");
  }
  return payload.result;
}

function validateHexResult(value, bytecode = false) {
  const pattern = bytecode ? /^0x(?:[0-9a-fA-F]{2})*$/ : /^0x[0-9a-fA-F]+$/;
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new EthereumRpcError("bad_response", "Ethereum RPC returned an invalid result.");
  }
  return value;
}

async function checkEthereumContract(address, options = {}) {
  if (!validateContractAddress(address)) {
    throw new EthereumRpcError("invalid_address", "A 20-byte hexadecimal contract address is required.");
  }

  const env = options.env || process.env;
  const endpoint = getEndpoint(env);
  const fetchImpl = options.fetchImpl || activeFetch;
  const timeoutMs = options.timeoutMs || getTimeoutMs(env);
  const maxResponseBytes = options.maxResponseBytes || DEFAULT_MAX_RESPONSE_BYTES;
  let nextId = 1;

  async function request(method, params) {
    const id = nextId;
    nextId += 1;
    const controller = new AbortController();
    let timer;

    const requestPromise = (async () => {
      let response;
      try {
        response = await fetchImpl(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
          signal: controller.signal,
          redirect: "error"
        });
      } catch {
        throw new EthereumRpcError(
          controller.signal.aborted ? "timeout" : "network",
          controller.signal.aborted
            ? "Ethereum RPC request timed out."
            : "Ethereum RPC request failed."
        );
      }

      if (!response || typeof response.ok !== "boolean") {
        throw new EthereumRpcError("bad_response", "Ethereum RPC returned an unreadable response.");
      }
      if (!response.ok) {
        throw new EthereumRpcError("http_rejection", "Ethereum RPC rejected the request.");
      }

      let text;
      try {
        text = await readBoundedText(response, maxResponseBytes);
      } catch (error) {
        if (error instanceof EthereumRpcError) {
          throw error;
        }
        throw new EthereumRpcError("bad_response", "Ethereum RPC returned an unreadable response.");
      }

      let payload;
      try {
        payload = JSON.parse(text);
      } catch {
        throw new EthereumRpcError("bad_response", "Ethereum RPC returned malformed JSON.");
      }
      return parseRpcResponse(payload, id);
    })();

    const timeoutPromise = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new EthereumRpcError("timeout", "Ethereum RPC request timed out."));
      }, timeoutMs);
    });

    try {
      return await Promise.race([requestPromise, timeoutPromise]);
    } finally {
      clearTimeout(timer);
    }
  }

  const normalizedAddress = address.toLowerCase();
  const [chainIdValue, blockNumberValue, codeValue] = await Promise.all([
    request("eth_chainId", []),
    request("eth_blockNumber", []),
    request("eth_getCode", [normalizedAddress, "latest"])
  ]);
  const chainId = validateHexResult(chainIdValue);
  const latestBlock = validateHexResult(blockNumberValue);
  const bytecode = validateHexResult(codeValue, true);

  return {
    address: normalizedAddress,
    chainId,
    latestBlock,
    codeStatus: bytecode === "0x" ? "no_bytecode" : "bytecode_present"
  };
}

module.exports = {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  ETHEREUM_ADDRESS_PATTERN,
  EthereumRpcError,
  checkEthereumContract,
  setEthereumRpcFetch,
  validateContractAddress
};
