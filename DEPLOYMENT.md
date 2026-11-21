# ChainShield deployment readiness

This guide prepares a Vercel deployment of the existing Express backend and a separate Chrome extension package. Nothing in these steps deploys automatically from this workspace.

## Verification status

- **Supabase integration in source:** implemented. The backend calls Supabase PostgREST RPC over HTTPS; browser code never receives the Supabase key.
- **Local Supabase configuration:** `server/.env` contains non-empty `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `COMMUNITY_HASH_SECRET`, and `COMMUNITY_ADMIN_TOKEN` values in the audited workspace as of 2026-11-20. This confirms local configuration only; the values are intentionally not recorded here.
- **Remote Supabase connection:** not verified in this audit. No Preview API URL was available, so no remote API request was made. Earlier reported integration checks are historical and are not a substitute for a current check.
- **Vercel Preview and Production deployments:** neither was verified in this audit. No deployment was performed.

The application supports live Supabase when the variables above are set and the migration has been applied to the corresponding project. Do not interpret local configuration or a successful `/api/health` response as proof of remote database connectivity.

## Hosting compatibility

The app factory in `server/src/app.js` exports the Express app and calls `listen()` only when started directly. `server/index.js` exports that app as Vercel's recognized Express entry point. `server/vercel.json` sets a 60 second function maximum for sequential optional contract-source lookups. Configure Vercel's **Root Directory** as `server`; this makes the backend's package manifest and lockfile the project's dependency root. Express handles the existing `/api/...` paths directly, without a rewrite adapter.

The runtime uses Node built-ins available in Node 24, standard `fetch`, `AbortController`, and server-side HTTPS requests. Supabase uses PostgREST RPC over HTTPS, so it does not require a persistent database socket or local disk. The local `.env` file is not required in Vercel; configure values in Project Settings instead. A Vercel build and deployment have not been verified in this audit, so verify Preview before promoting it.

`GET /api/health` only confirms the backend process. To check Supabase configuration and RPC access, call `GET /api/community/domains/<your-domain>` after setup and expect HTTP 200. The endpoint currently returns 503 when community storage is unavailable.

The backend accepts Chrome extension origins for CORS and does not use cookies. The production extension build below grants access only to the configured HTTPS API origin. It contains no backend keys.

## Environment variables

All variables are optional for process startup; individual integrations fail closed or return unavailable when their configuration is absent. Set the following to enable the listed production capabilities:

| Variable | Needed for | Notes |
|---|---|---|
| `TINYFISH_API_KEY` | Search evidence | Required for complete web-search results; investigations remain partial if it is absent. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Threat lookups | Required for Safe Browsing verdict coverage; without it the threat assessment is unavailable. |
| `SUPABASE_URL` | Community reports | Project API URL, e.g. `https://<project-ref>.supabase.co`. |
| `SUPABASE_SECRET_KEY` | Community reports | Prefer a new `sb_secret_…` key. The backend keeps it server-side. A legacy `service_role` JWT is still supported. |
| `COMMUNITY_HASH_SECRET` | Report submissions | Use a random secret of at least 32 characters. It keys reporter IP HMACs. |
| `COMMUNITY_ADMIN_TOKEN` | Moderation | Use a separate random secret of at least 32 characters. Required for moderation API calls. |
| `ETH_RPC_URL` | Optional Web3 network check | Must be an HTTPS endpoint. |
| `ETHERSCAN_API_KEY` | Optional verified source analysis | Needed for source lookup and proxy metadata. |
| `PORT` | Local server binding | Vercel supplies its own function runtime; do not set this in Vercel. Local default is 3000. |
| `TRUST_PROXY_HOPS` | Client IP/rate limit | Set to `1` for Vercel's standard proxy. Leave other integrations independent. |
| `TINYFISH_TIMEOUT_MS` | Optional tuning | Defaults to 8000 ms. |
| `GOOGLE_SAFE_BROWSING_TIMEOUT_MS` | Optional tuning | Defaults to 6000 ms. |
| `ETH_RPC_TIMEOUT_MS` | Optional tuning | Defaults to 6000 ms per request. |
| `ETHERSCAN_TIMEOUT_MS` | Optional tuning | Defaults to 6000 ms per request. |

Never set any backend key in `extension/config.js`, the extension manifest, or Chrome's extension package. In Vercel, add secrets through Project Settings → Environment Variables, mark them sensitive where available, and select only the environments that need them. Do not paste their values into build logs or tickets.

## Supabase setup and verification

The application expects tables `public.community_reports` and `public.community_rate_limits`, plus RPC functions `community_submit_report`, `community_public_summary`, `community_moderation_queue`, and `community_moderate_report`. The backend sends named `p_*` parameters matching `server/migrations/001_community_reports.sql`. The migration creates both tables, indexes, row-level-security settings, and these four functions; it is not automatically executed during deployment. Static tests check the migration contract, but do not execute SQL against Supabase.

If a project has not already been created:

1. Sign in to the Supabase Dashboard, choose or create an organization, then select **New project**. Choose a project name, region, and a strong database password; wait until provisioning completes.
2. In the project dashboard open **SQL Editor** → **New query**. Copy all of `server/migrations/001_community_reports.sql`, run it once, and confirm the query succeeds.
3. Open **Integrations → Data API** to copy the project URL. Open **Settings → API Keys** and create/copy a secret key (`sb_secret_…`). Use the secret key, not the publishable key. If only legacy keys are available, use the `service_role` key; do not use `anon`/publishable keys for this backend. Supabase documents new secret keys as server-only and says to send them in `apikey`, not `Authorization: Bearer`; this backend now follows that behavior while retaining legacy JWT compatibility.
4. In Vercel Project Settings → Environment Variables, set `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `COMMUNITY_HASH_SECRET`, and `COMMUNITY_ADMIN_TOKEN`. Generate the last two independently with a password manager or cryptographically secure generator; both need at least 32 characters. Add the provider keys described above for the features you want enabled.
5. Redeploy a Preview after setting variables. Test RPC connectivity without creating a report:

   ```powershell
   $apiRoot = "https://<your-preview-domain>/api"
   Invoke-RestMethod "$apiRoot/community/domains/<your-owned-test-domain>"
   ```

   Expect HTTP 200 and a zero-report summary for a new domain. This also confirms the API URL/key, migration functions, and backend RPC wiring. The regular health endpoint does not check Supabase.

6. On Preview, submit a report for a domain you control. Confirm the response status is `pending`, then confirm it appears in the protected moderation queue but not in the public summary. Approve it, re-read the public summary, and confirm it appears. Submit a second report and exercise `reject`; approve a separate report and exercise `remove`. The public summary must never expose pending or rejected rows. Duplicate normalized submissions should return 409; the sixth submission from the same network identifier within an hour should return 429. Use disposable staging/test data and remove it after checks.

Example moderation calls (set `$env:COMMUNITY_ADMIN_TOKEN` locally without echoing its value):

```powershell
$headers = @{ Authorization = "Bearer $env:COMMUNITY_ADMIN_TOKEN" }
Invoke-RestMethod "$apiRoot/community/admin/reports" -Headers $headers
$reportId = "<pending-report-uuid>"
$body = @{ action = "approve" } | ConvertTo-Json
Invoke-RestMethod "$apiRoot/community/admin/reports/$reportId/moderation" -Method Post -Headers $headers -ContentType "application/json" -Body $body
```

The migration and RPC contract are covered by static tests. Live SQL execution and current remote RPC behavior were not verified in this audit. When an existing Preview API URL is available, use the read-only checks below before exercising any write or moderation workflow.

### Read-only Preview checks

Use a known Preview API URL supplied by the project owner; do not infer a Vercel URL from the repository. `GET /api/health` checks only that the API process responds. Then request `GET /api/community/domains/<test-domain>` for a domain selected for testing. A successful response should include the requested normalized domain, integer `totalApproved`, `categoryCounts`, an array of `recentReports`, `source: "community_reports"`, and `trust: "unverified_user_submissions"`. The database function selects only rows whose status is `approved`. A 503 indicates the community store or its configuration/RPC is unavailable; it does not affect investigation verdicts. These GET checks do not write database rows.

## Vercel deployment steps

1. Review and push the approved code to a Git provider yourself; no repository changes are pushed by these instructions.
2. In Vercel, import the repository and set **Root Directory** to `server`. Select or confirm the Express framework preset. Vercel will install dependencies from `server/package-lock.json`; leave Install Command and Build Command at their defaults. `server/vercel.json` sets the 60 second function limit.
3. Select Node.js 24 in Project Settings → General → Node.js Version. The local audit used Node 24.20.0; the checked-in app requires Node 18+ platform primitives, but production should use the current supported LTS line.
4. Add required integration environment variables in Vercel for Preview first. Set `TRUST_PROXY_HOPS=1` for the standard Vercel proxy. Do not set `PORT`.
5. Create a Preview deployment. Check its build logs for successful `npm ci` from `server`, then check `GET https://<preview-domain>/api/health` returns `{"status":"ok"}`. Check the community GET call for a successful RPC. Run the end-to-end cases below before promoting to Production.
6. Set the Production environment variables, then use Vercel's dashboard to promote the reviewed Preview or create the production deployment. Confirm the production health endpoint and remote extension build before distributing the extension.

Vercel documents Express as a Node.js Function and supports a function-specific `maxDuration` in `vercel.json`. The configured 60 seconds is intended to cover the app's sequential bounded Etherscan proxy lookups; confirm it is within the selected account's plan limits. A Vercel build/deployment was not run in this audit.

## Production extension build

Keep `extension/config.js` and `extension/manifest.json` unchanged for local development. Build a separate package after the backend Preview or Production URL is known:

```powershell
$apiBase = "https://<your-backend-domain>/api"
node scripts/build-extension.js $apiBase
```

The script rejects non-HTTPS URLs, writes `dist/extension`, sets the configured API base, and replaces localhost host access with exactly that API origin. It does not include test files or secrets. Local unpacked development remains the source `extension` folder, which defaults to `http://localhost:3000/api` and declares `http://localhost/*`.

Load `dist/extension` through `chrome://extensions` → Developer mode → Load unpacked and run the remote extension checks below. For Chrome Web Store submission, zip the *contents* of `dist/extension` so `manifest.json` is at the ZIP root:

```powershell
Compress-Archive -Path dist/extension/* -DestinationPath dist/ChainShield.zip -Force
```

Before distributing, inspect `dist/extension/config.js` and `manifest.json`: the API value must be your HTTPS backend, the host permission must match its origin, and no localhost permission or backend key should be present.

## End-to-end validation plan

Run provider-backed checks against Preview with URLs and report data you are authorized to use. Provider databases can change, so treat live outputs as observations rather than fixed assertions.

| Area | Test case | Expected result |
|---|---|---|
| Investigation | Google Safe Browsing test URL from Google's test documentation | Safe Browsing reports a match; verdict is known threat even if TinyFish is unavailable. Do not browse the test URL. |
| Investigation | URL with structural indicators, such as a long nested hostname or punycode label | Heuristic findings appear separately; verdict says suspicious indicators, not proven malicious. |
| Investigation | A clean-looking URL with no provider match | `no_known_threats_found` only when the configured checks complete; wording must not guarantee safety. |
| Investigation | Force TinyFish failure while Safe Browsing is reachable | HTTP 200 partial response; the available provider and verdict remain present. |
| Investigation | Force both search and Safe Browsing providers to fail | HTTP 200 partial response and inconclusive verdict; no fabricated clean result. Use automated mocks for repeatability. |
| Investigation | Missing, malformed, and `file:` URLs | HTTP 400 and no provider calls. |
| Safe Alternatives | Use a concerning URL with strong evidence for a supported category and current catalogue entries | Recommendations appear only when inference and verdict qualify; listing and official-domain sources remain visible. |
| Safe Alternatives | Use supported category evidence with no current catalogue entry | Honest empty state; no invented recommendations. |
| Safe Alternatives | Use mixed/ambiguous evidence | Category is `unknown`; no recommendations. |
| Safe Alternatives | Inspect a displayed verified recommendation | Official-domain link and source/provenance are present; trust is not guaranteed. |
| Community | Submit a valid report for a test domain you control | HTTP 202 and `pending`; report appears in admin queue only. |
| Community | Fetch public summary before approval | Pending report is absent. |
| Community | Approve, reject, then remove separate test reports | Approved appears publicly; rejected and removed do not. |
| Community | Repeat same normalized report; then exceed five submissions/hour from one IP | Duplicate returns HTTP 409; limit returns HTTP 429. |
| Community | Temporarily remove Supabase config or test an unavailable DB in a separate Preview | Community section reports unavailable; investigation/verdict still works. |
| Extension | Stop backend, then investigate | Clear backend error; no uncaught popup failure. |
| Extension | Run normal investigation and open Community section | Results and reports load; community errors do not alter verdict. |
| Extension | Submit invalid form fields and simulate API validation/429/503 responses | Native required/length/URL constraints work; response error is visible and form can be retried. |
| Extension | Build with Preview URL and inspect manifest/config | HTTPS API origin is configured exactly; localhost is absent from production host permissions. |
| Extension | Open production build in Chrome and perform investigation/report flow | CORS preflight and host permission allow requests to the configured remote API. |

The automated suite covers mocked provider failures, migration contract assertions, RPC request headers, form behavior, and extension build output. It cannot prove live API quotas, live Google threat list contents, Chrome Web Store approval, Vercel bundling, or live Supabase execution.

## Known deployment limitation

The integration currently calls Google Safe Browsing API v4. Google's current documentation marks Safe Browsing APIs v4 deprecated and says Safe Browsing is for non-commercial use; commercial use should use Web Risk. Confirm the intended product use and Google terms before a public commercial launch. Migrating providers would be a separate integration change and is not included in deployment preparation.
