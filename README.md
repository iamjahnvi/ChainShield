# ChainShield prototype

ChainShield is a Chrome Extension Manifest V3 popup connected to a local Express API. For a submitted website the backend runs a focused web search through the TinyFish Search API and returns the public sources it finds, with a clearly non-definitive, evidence-based summary. It does not scan, assess, or label the website as safe, suspicious, or malicious.

## Requirements

- Node.js 18 or newer (for the built-in `fetch` API and test runner)
- Google Chrome
- A TinyFish API key stored in `server/.env` (see below)

## Secret configuration

The backend reads `TINYFISH_API_KEY` from `server/.env`, loaded with `dotenv`.

1. Copy `server/.env.example` to `server/.env`.
2. Fill in `TINYFISH_API_KEY` in `server/.env` using your own value.
3. Keep `server/.env` private. `.gitignore` excludes `.env` files, and the key must never be placed in source code, the extension, API responses, or this README.

If the key is missing, the server still starts but prints a configuration warning, and investigation requests fail with a clear configuration error (HTTP 503). The key is only ever sent from the backend to the TinyFish API in the `X-API-Key` header.

## Run the backend on Windows

Open PowerShell in the project folder and run:

```powershell
cd .\server
npm install
npm test
npm start
```

The server listens on `http://localhost:3000` by default. To use another port, set `$env:PORT` before `npm start`; the extension's API URL must then be updated in `extension/popup.js` to match.

Check the health endpoint in another PowerShell window:

```powershell
Invoke-RestMethod http://localhost:3000/api/health
```

Try an investigation request:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://localhost:3000/api/investigations `
  -ContentType "application/json" `
  -Body '{"url":"https://example.com"}'
```

A successful response looks like:

```json
{
  "status": "research_available",
  "summary": "Web search returned sources for review. These results do not establish whether the website is safe or malicious.",
  "domain": "example.com",
  "evidence": [
    {
      "title": "Example source",
      "url": "https://source.example/report",
      "snippet": "Available search-result excerpt",
      "source": "TinyFish Search"
    }
  ],
  "investigationType": "web_search",
  "demo": false
}
```

If the search returns nothing, the response uses `"status": "no_results"` with an empty `evidence` array and a summary stating that this does not mean the website is safe.

## Load the extension in Chrome

1. Keep the backend running.
2. Visit `chrome://extensions` in Chrome.
3. Turn on **Developer mode**.
4. Select **Load unpacked** and choose this project's `extension` folder.
5. Open a regular `http://` or `https://` website.
6. Open the Extensions menu, pin ChainShield if desired, and select its icon.
7. Select **Investigate this website**. While the backend searches, the popup shows a loading message; afterwards it shows the hostname, a **WEB SEARCH** badge, and the returned public sources with clickable titles (each opens in a new tab only when you click it).
8. Open a Chrome internal page such as `chrome://settings`, open ChainShield, and confirm it explains that the page cannot be investigated.

To reload after code changes: revisit `chrome://extensions` and press the refresh icon on the ChainShield card, then reopen the popup.

## Important files

- `extension/manifest.json` tells Chrome that this is a Manifest V3 extension, requests `activeTab` to read the current tab after the user opens the extension, and permits requests to the local `localhost` backend.
- `extension/popup.html` defines the popup content, the WEB SEARCH badge, and accessible status/result regions.
- `extension/popup.css` provides the popup's layout, colors, and focus/disabled states.
- `extension/popup.js` reads the active tab, blocks unsupported protocols, calls the local API, and displays loading, success, empty, and error states. Source links are only rendered as clickable when they validate as `http://` or `https://` URLs.
- `server/package.json` declares Express, dotenv, and the commands to start and test the backend.
- `server/src/app.js` loads `server/.env` with dotenv, configures the Express app, local development CORS, health endpoint, and JSON error handling.
- `server/src/tinyfish.js` builds the search query, calls the TinyFish Search endpoint with the backend-held API key, applies a request timeout, and validates/normalizes search results.
- `server/src/routes/investigations.js` validates submitted URLs and maps search outcomes (results, no results, and upstream failures) to API responses.
- `server/test/app.test.js` exercises the health endpoint and invalid URL cases.
- `server/test/investigations.test.js` exercises the TinyFish integration with mocked responses (no live API quota is consumed).

## Development CORS

The API accepts browser cross-origin requests only when their origin matches the format of a Chrome extension ID (`chrome-extension://` followed by 32 characters from `a` to `p`). This accommodates IDs Chrome assigns to locally loaded extensions while excluding ordinary website origins. Requests without an `Origin` header, such as local PowerShell checks, are also supported. This is a local prototype configuration, not production deployment guidance.

## Prototype limitations

- Results are limited to what a single web search returns; the absence of results is never a safety verdict, and the presence of results is not a security scan or verification.
- The TinyFish API key stays in the backend only; the extension and API responses never receive it.
- The extension expects the backend at `http://localhost:3000`.
- The popup is manually verified in Chrome; automated browser/extension integration testing is not included.
