# ytm-chatgpt-apps · ChatGPT ↔ YouTube Playlist Builder (MCP-ready)

Open-source Node server that lets ChatGPT search YouTube, create playlists, and add tracks using the official YouTube Data API v3. It includes:

- A minimal REST API for manual testing.
- A [Model Context Protocol (MCP)](https://developers.openai.com/apps-sdk/build/mcp-server) transport at `/mcp`, so you can register it as a ChatGPT App Connector with zero extra glue code.

## Features
- OAuth 2.0 dance for end users (stored in-memory per `userKey`).
- REST endpoints: `/search`, `/playlists`, `/playlists/:id/items`.
- MCP tools mirroring those endpoints: `search_music_videos`, `create_playlist`, `add_videos_to_playlist`.
- ngrok-friendly, HTTPS-only testing workflow with optional origin/host allowlists for DNS-rebinding protection.

## Prerequisites
- Node.js 18+
- A Google Cloud project with **YouTube Data API v3** enabled
- OAuth 2.0 Client (type **Web application**) with redirect URI `http://localhost:3000/oauth2/callback`
- (Optional) ngrok or another HTTPS tunnel when exposing the server to ChatGPT

## Quick Start
```bash
git clone https://github.com/YOUR_ORG/ytm-chatgpt-apps.git
cd ytm-chatgpt-apps
cp .env.example .env   # fill GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
npm install
npm start              # or: npm run dev (watch mode)
```

## Environment variables
| Name | Purpose |
| --- | --- |
| `PORT` | Local port (defaults to `3000`). |
| `ALLOWED_ORIGINS` | CSV of origins allowed to call the REST API. Leave blank to allow any during dev. |
| `MCP_ALLOWED_ORIGINS` | Origins allowed on MCP transport. Defaults to `https://chat.openai.com`; set empty while tunneling if the client omits `Origin`. |
| `MCP_ALLOWED_HOSTS` | Optional host allowlist for MCP (use your ngrok hostname for extra protection). |
| `PUBLIC_BASE_URL` | Public HTTPS origin (use your ngrok HTTPS URL during dev). Used to mint the OAuth metadata URL and resource identifier. |
| `AUTH_ISSUER` / `AUTH_AUDIENCE` | Values expected inside the ChatGPT-issued OAuth access token. Usually matches your IdP (Auth0/Okta/etc.). |
| `AUTH_JWKS_URL` | JWKS endpoint for verifying bearer tokens. |
| `AUTH_AUTHORIZATION_ENDPOINT` / `AUTH_TOKEN_ENDPOINT` / `AUTH_REGISTRATION_ENDPOINT` | Optional overrides so the `.well-known/oauth-protected-resource` response can reference your IdP endpoints. |
| `AUTH_REQUIRED_SCOPES` | Space- or comma-separated scopes ChatGPT must request (e.g. `ytm.playlists`). |
| `AUTHORIZATION_SERVERS` | Extra authorization-server issuers to advertise (comma separated). |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Credentials for YouTube Data API OAuth. |
| `GOOGLE_REDIRECT_URI` | Usually `http://localhost:3000/oauth2/callback` in dev. |

## Authorize a Google account
Each ChatGPT user must run the Google OAuth flow once so the server can store a refresh token keyed by the Auth0 `sub`. When a tool complains “Not authorized yet…”, have the user visit the provided link (e.g. `https://YOUR_DOMAIN/auth/start?userKey=google-oauth2%7C123…`) to finish the flow and return to ChatGPT. Tokens are cached in-memory per user; replace the store before shipping to prod.

> Dev escape hatch: if you leave `AUTH_ISSUER/AUDIENCE/JWKS_URL` empty, the server falls back to accepting `X-User-Key` headers so you can run curl tests without the IdP. Don’t rely on this mode in production.

## Smoke test the REST API
Use a bearer token minted by your IdP once you’ve configured the OAuth settings:

```bash
ACCESS_TOKEN="eyJhbGciOi..."   # issued by your IdP for the resource ${PUBLIC_BASE_URL}/mcp

# Create a playlist
curl -sX POST 'http://localhost:3000/playlists' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"name":"Friday Test","privacyStatus":"unlisted"}'

# Search tracks
curl -s 'http://localhost:3000/search?q=lofi%20jazz&max=5' \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# Add items
curl -sX POST 'http://localhost:3000/playlists/PLAYLIST_ID/items' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"videoIds":["VIDEO_ID_1","VIDEO_ID_2"]}'
```

> Still running without OAuth? Replace the bearer header with `-H 'X-User-Key: YOUR_DEV_KEY'` until your IdP is ready.

## Expose locally via ngrok
The official `@openai/actions` dev proxy isn’t public yet, so use ngrok (or similar) when connecting ChatGPT to your laptop:

```bash
brew install ngrok        # or download from ngrok.com
ngrok config add-authtoken <YOUR_TOKEN>
npm start                 # run the API locally
ngrok http http://localhost:3000
# Copy the HTTPS URL, e.g. https://granite-emu.ngrok-free.app
```

Keep the tunnel running as long as ChatGPT needs to reach your server.

## ChatGPT Apps MCP connector

1. Turn on **Developer mode** in ChatGPT (Settings → Apps & Connectors → Developer mode).
2. Make sure your `.env` has the OAuth settings populated (`PUBLIC_BASE_URL`, `AUTH_ISSUER`, `AUTH_AUDIENCE`, `AUTH_JWKS_URL`, etc.) and that `/.well-known/oauth-protected-resource` is reachable over HTTPS (ngrok URL + path works during dev).
3. With `npm start` and ngrok running, create a new connector that points to your tunnel URL + `/mcp`, e.g. `https://sparkly-otter.ngrok-free.app/mcp`. ChatGPT automatically discovers the OAuth metadata and prompts users to sign in via your IdP the first time they call a tool.
4. After ChatGPT completes the in-chat OAuth flow, open a fresh conversation, click `+` near the composer → **More** → select the connector.
5. Try this mini-playthrough:
   - “Search 3 upbeat lofi tracks for my Pomodoro Mix playlist.”
   - “Create a private playlist called Pomodoro Mix.”
   - “Add the tracks you just found to the Pomodoro Mix playlist.”
6. When a user hasn’t linked their YouTube account yet, the tool will reply with the `auth/start?userKey=<sub>` URL they can click. Once they finish the Google consent screen, run the prompt again.
7. Inspect tool calls and responses in the chat sidebar or attach MCP Inspector to the same URL for debugging.

## Tool reference
| Tool | Purpose | Required args |
| --- | --- | --- |
| `search_music_videos` | Music-biased YouTube search (topic `/m/04rlf`). | `query`, optional `max` (1–50). |
| `create_playlist` | Creates a playlist in the authenticated channel. | `name`, optional `description`, `privacyStatus`. |
| `add_videos_to_playlist` | Inserts videos to a playlist. | `playlistId`, `videoIds[]`. |

Each tool returns both human-readable text and `structuredContent` so the model can chain results.

## Project structure
```
src/app.js        # Express + MCP server (standalone + serverless entrypoint)
api/index.js      # Vercel serverless handler via serverless-http
vercel.json       # Vercel routing + runtime config
.env.example      # Environment variable template
```

Scripts:
- `npm start` – run the server once
- `npm run dev` – run with `node --watch` (beware file watch limits on macOS)

## Production notes
- Replace the in-memory token store with encrypted storage.
- Enforce HTTPS (ngrok/Cloudflare Tunnel are fine for dev, but deploy to a public host before sharing widely).
- Set `ALLOWED_ORIGINS`, `MCP_ALLOWED_ORIGINS`, and `MCP_ALLOWED_HOSTS` to the exact values you expect in production to prevent DNS rebinding.

## Deploy to Vercel
1. **Connect the repo.** Push this repo to GitHub/GitLab and create a new Vercel project that points at it. Vercel reads `vercel.json`, builds dependencies with `npm install`, and serves every route through `api/index.js`, which wraps the Express app with `serverless-http`.
2. **Configure environment variables.** In Vercel → Project Settings → Environment Variables, add the same keys you use locally (`GOOGLE_CLIENT_ID/SECRET`, `AUTH_*`, etc.). Set `PUBLIC_BASE_URL` to your Vercel hostname (e.g. `https://ytm-chatgpt-apps.vercel.app`) and update `GOOGLE_REDIRECT_URI` to `https://<project>.vercel.app/oauth2/callback` so Google accepts the redirect.
3. **Protect secrets.** Keep OAuth credentials and IdP metadata in Vercel’s encrypted config rather than committing them, aligning with the Apps SDK guidance to store secrets in your hosting platform and inject them at runtime.citeturn1view0
4. **Deploy & verify.** Trigger a production deploy. Once live, hit `https://<project>.vercel.app/mcp` (HEAD + GET) and `/.well-known/oauth-protected-resource` to ensure the HTTPS endpoint streams correctly. The Apps SDK docs call out that whatever platform you choose must keep `/mcp` responsive, support streaming responses, and return proper HTTP codes, so test with MCP Inspector or curl before connecting ChatGPT.citeturn1view0
5. **Connect ChatGPT.** In ChatGPT (Developer mode), register the connector using the Vercel URL + `/mcp`, then rerun your golden prompts. Keep an eye on Vercel logs/metrics for latency spikes; if you need more headroom, adjust `maxDuration`/`memory` in `vercel.json`.

Tip: during dogfooding, you can run `vercel env pull` to sync env vars locally and `vercel dev` to emulate rewrites before pushing changes.

## License
Add your favorite SPDX license here before publishing (MIT is common for simple servers).

## Contributing
Issues and PRs are welcome! Please include:
1. A description of the feature/bugfix.
2. Steps to reproduce (for bugs).
3. Tests or manual verification notes (curl commands, ChatGPT prompt transcripts, etc.).

## FAQ
**Where do I see tool logs?** – The server logs each MCP request with `[mcp]` prefixes, including session IDs. Use them to trace ChatGPT conversations.

**How do I switch accounts?** – Disconnect/reconnect the connector in ChatGPT (it will rerun the OAuth flow) or use the IdP’s session management UI to sign out, then issue a new tool call.

**Why do I get Origin errors?** – If requests arrive without an `Origin` header (common over ngrok), leave `MCP_ALLOWED_ORIGINS` empty during dev.

Happy playlist building!
