const API_URL = "http://localhost:3000/api/investigations";
const VALID_STATUSES = ["research_available", "no_results"];

const button = document.querySelector("#investigate-button");
const domainLabel = document.querySelector("#page-domain");
const message = document.querySelector("#message");
const result = document.querySelector("#result");
const resultStatus = document.querySelector("#result-status");
const resultSummary = document.querySelector("#result-summary");
const evidenceList = document.querySelector("#evidence-list");

function setMessage(text, state = "") {
  message.textContent = text;
  if (state) {
    message.dataset.state = state;
  } else {
    delete message.dataset.state;
  }
}

function isSupportedUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function buildEvidenceItem(entry) {
  const item = document.createElement("li");

  const title =
    typeof entry.title === "string" && entry.title.trim() !== ""
      ? entry.title.trim()
      : "";
  const url =
    typeof entry.url === "string" && isSupportedUrl(entry.url) ? entry.url : "";

  if (url) {
    const link = document.createElement("a");
    link.href = url;
    link.textContent = title || url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    item.append(link);
  } else if (title) {
    const label = document.createElement("span");
    label.textContent = title;
    item.append(label);
  }

  if (typeof entry.snippet === "string" && entry.snippet.trim() !== "") {
    const snippet = document.createElement("p");
    snippet.className = "evidence-snippet";
    snippet.textContent = entry.snippet.trim();
    item.append(snippet);
  }

  const metaParts = [];
  if (typeof entry.siteName === "string" && entry.siteName.trim() !== "") {
    metaParts.push(entry.siteName.trim());
  }
  if (typeof entry.position === "number" && Number.isFinite(entry.position)) {
    metaParts.push(`Result #${entry.position}`);
  }
  metaParts.push(
    typeof entry.source === "string" && entry.source.trim() !== ""
      ? entry.source.trim()
      : "Web search"
  );

  const meta = document.createElement("p");
  meta.className = "evidence-meta";
  meta.textContent = metaParts.join(" · ");
  item.append(meta);

  return item;
}

function displayResult(data) {
  resultStatus.textContent =
    data.status === "no_results"
      ? "Web search found no sources — this is not a safety verdict."
      : "Web search sources — not a verified security finding.";
  resultSummary.textContent = data.summary;
  evidenceList.replaceChildren();

  if (!Array.isArray(data.evidence) || data.evidence.length === 0) {
    const item = document.createElement("li");
    item.className = "evidence-empty";
    item.textContent =
      data.status === "no_results"
        ? "No public sources were found for this website."
        : "No sources were returned.";
    evidenceList.append(item);
  } else {
    for (const entry of data.evidence) {
      evidenceList.append(buildEvidenceItem(entry));
    }
  }

  result.hidden = false;
}

button.addEventListener("click", async () => {
  button.disabled = true;
  result.hidden = true;
  domainLabel.textContent = "";
  setMessage("Checking the active tab…");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url || !isSupportedUrl(tab.url)) {
      setMessage("This page cannot be investigated. Open a website with an http:// or https:// address and try again.", "error");
      return;
    }

    const domain = new URL(tab.url).hostname;
    domainLabel.textContent = `Website: ${domain}`;
    setMessage(`Searching the web for public sources about ${domain}…`, "loading");

    let response;
    try {
      response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: tab.url })
      });
    } catch {
      throw new Error("Could not reach the local server. Make sure it is running on port 3000.");
    }

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("The server returned an invalid response. Check that the backend is running correctly.");
    }

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("The server returned an invalid response. Check that the backend is running correctly.");
    }

    if (!response.ok) {
      throw new Error(data.error || `The server returned an error (${response.status}).`);
    }

    if (
      !VALID_STATUSES.includes(data.status) ||
      data.investigationType !== "web_search" ||
      typeof data.summary !== "string" ||
      !Array.isArray(data.evidence) ||
      typeof data.domain !== "string"
    ) {
      throw new Error("The server response was missing expected investigation details.");
    }

    displayResult(data);

    if (data.status === "no_results") {
      setMessage("Search finished, but no public sources were found for this website.");
    } else {
      setMessage("Web search complete. Review the sources below — no security scan was performed.", "success");
    }
  } catch (error) {
    setMessage(error instanceof Error ? error.message : "Something went wrong while contacting the server.", "error");
  } finally {
    button.disabled = false;
  }
});
