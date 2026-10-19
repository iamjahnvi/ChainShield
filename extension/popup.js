const API_URL = "http://localhost:3000/api/investigations";

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

function displayResult(data) {
  resultStatus.textContent = `Status: ${data.status}`;
  resultSummary.textContent = data.summary;
  evidenceList.replaceChildren();

  if (data.evidence.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No evidence items in this demo response.";
    evidenceList.append(item);
  } else {
    for (const evidence of data.evidence) {
      const item = document.createElement("li");
      item.textContent = typeof evidence === "string"
        ? evidence
        : JSON.stringify(evidence);
      evidenceList.append(item);
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
    setMessage("Sending the URL to the local demo server…");

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
      data.status !== "not_yet_investigated" ||
      typeof data.summary !== "string" ||
      !Array.isArray(data.evidence) ||
      typeof data.domain !== "string"
    ) {
      throw new Error("The server response was missing expected investigation details.");
    }

    displayResult(data);
    setMessage("Demo result received. No real security investigation was performed.", "success");
  } catch (error) {
    setMessage(error instanceof Error ? error.message : "Something went wrong while contacting the server.", "error");
  } finally {
    button.disabled = false;
  }
});
