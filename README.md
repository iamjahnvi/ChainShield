# ChainShield prototype

ChainShield is a small Chrome Extension Manifest V3 popup connected to a local Express API. The investigation response is mock data: it does not scan, assess, or label the website as safe, suspicious, or malicious.

## Requirements

- Node.js 18 or newer (for the built-in `fetch` API and test runner)
- Google Chrome

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

## Load the extension in Chrome

1. Keep the backend running.
2. Visit `chrome://extensions` in Chrome.
3. Turn on **Developer mode**.
4. Select **Load unpacked** and choose this project's `extension` folder.
5. Open a regular `http://` or `https://` website.
6. Open the Extensions menu, pin ChainShield if desired, and select its icon.
7. Select **Investigate this website**. The popup should show the hostname and a clearly marked demo result.
8. Open a Chrome internal page such as `chrome://settings`, open ChainShield, and confirm it explains that the page cannot be investigated.

## Important files

- `extension/manifest.json` tells Chrome that this is a Manifest V3 extension, requests `activeTab` to read the current tab after the user opens the extension, and permits requests to the local `localhost` backend.
- `extension/popup.html` defines the popup content and accessible status/result regions.
- `extension/popup.css` provides the popup's layout, colors, and focus/disabled states.
- `extension/popup.js` reads the active tab, blocks unsupported protocols, calls the local API, and displays loading, success, and error states.
- `server/package.json` declares Express and the commands to start and test the backend.
- `server/src/app.js` configures the Express app, local development CORS, health endpoint, and JSON error handling.
- `server/src/routes/investigations.js` validates submitted URLs and returns the deterministic mock investigation response.
- `server/test/app.test.js` exercises the health endpoint, valid response, and invalid URL cases.

## Development CORS

The API accepts browser cross-origin requests only when their origin matches the format of a Chrome extension ID (`chrome-extension://` followed by 32 characters from `a` to `p`). This accommodates IDs Chrome assigns to locally loaded extensions while excluding ordinary website origins. Requests without an `Origin` header, such as local PowerShell checks, are also supported. This is a local prototype configuration, not production deployment guidance.

## Prototype limitations

- Results are fixed demo data; no real investigation is performed.
- The extension expects the backend at `http://localhost:3000`.
- The popup is manually verified in Chrome; automated browser/extension integration testing is not included.
