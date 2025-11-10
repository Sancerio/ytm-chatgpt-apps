import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import crypto from "crypto";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { z } from "zod";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { google } from "googleapis";
import { createTokenStore } from "./tokenStore.js";

dotenv.config();

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI = "http://localhost:3000/oauth2/callback",
  ALLOWED_ORIGINS = "",
  MCP_ALLOWED_ORIGINS = "https://chat.openai.com",
  MCP_ALLOWED_HOSTS = "",
  PUBLIC_BASE_URL = "https://localhost",
  AUTH_ISSUER,
  AUTH_AUDIENCE,
  AUTH_JWKS_URL,
  AUTH_REQUIRED_SCOPES = "ytm.playlists",
  AUTH_AUTHORIZATION_ENDPOINT,
  AUTH_TOKEN_ENDPOINT,
  AUTH_REGISTRATION_ENDPOINT,
  AUTHORIZATION_SERVERS = "",
  REDIS_REST_URL,
  REDIS_REST_TOKEN,
  REDIS_NAMESPACE = "ytm_tokens",
} = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn("[WARN] Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in .env");
}

const parseCsv = (value = "") => value.split(",").map(s => s.trim()).filter(Boolean);
const allowedOrigins = parseCsv(ALLOWED_ORIGINS);
const allowedMcpOrigins = parseCsv(MCP_ALLOWED_ORIGINS);
const allowedMcpHosts = parseCsv(MCP_ALLOWED_HOSTS);
const requiredScopes = parseCsv(AUTH_REQUIRED_SCOPES);
const listedAuthServers = parseCsv(AUTHORIZATION_SERVERS).map(issuer => ({ issuer }));
const defaultAuthServerEntry = AUTH_ISSUER
  ? {
    issuer: AUTH_ISSUER,
    ...(AUTH_AUTHORIZATION_ENDPOINT && { authorization_endpoint: AUTH_AUTHORIZATION_ENDPOINT }),
    ...(AUTH_TOKEN_ENDPOINT && { token_endpoint: AUTH_TOKEN_ENDPOINT }),
    ...(AUTH_REGISTRATION_ENDPOINT && { registration_endpoint: AUTH_REGISTRATION_ENDPOINT }),
  }
  : null;
const publicBase = PUBLIC_BASE_URL.replace(/\/$/, "");
console.log(`[config] PUBLIC_BASE_URL resolved to ${publicBase}`);
const resourceId = `${publicBase}/mcp`;
const resourceMetadataUrl = `${publicBase}/.well-known/oauth-protected-resource`;
const oauthConfigured = Boolean(AUTH_ISSUER && AUTH_AUDIENCE && AUTH_JWKS_URL);
const authServersForMetadata = listedAuthServers.length ? listedAuthServers : (defaultAuthServerEntry ? [defaultAuthServerEntry] : []);
let jwks;
if (oauthConfigured) {
  jwks = createRemoteJWKSet(new URL(AUTH_JWKS_URL));
} else {
  console.warn("[WARN] OAuth config incomplete (AUTH_ISSUER/AUTH_AUDIENCE/AUTH_JWKS_URL). Falling back to X-User-Key header for dev only.");
}
const clampMaxResults = value => {
  const parsed = Number(value ?? 25);
  if (!Number.isFinite(parsed)) return 25;
  const rounded = Math.trunc(parsed);
  return Math.min(Math.max(rounded, 1), 50);
};

function sendUnauthorized(res, message, code = "invalid_token") {
  if (oauthConfigured) {
    res.setHeader("WWW-Authenticate", `Bearer realm="${resourceId}", resource="${resourceId}", error="${code}", error_description="${message}", resource_metadata="${resourceMetadataUrl}"`);
  }
  if (!res.headersSent) {
    res.status(401).json({ error: "unauthorized", message });
  }
}

async function authenticateRequest(req, res) {
  if (oauthConfigured) {
    const authHeader = req.header("authorization") || "";
    if (!authHeader.toLowerCase().startsWith("bearer ")) {
      sendUnauthorized(res, "Missing Authorization bearer token", "invalid_request");
      return null;
    }
    const token = authHeader.slice(7).trim();
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: AUTH_ISSUER,
      });
      const expectedAudience = Array.isArray(AUTH_AUDIENCE)
        ? AUTH_AUDIENCE.map(a => a.trim())
        : [AUTH_AUDIENCE.trim()];
      const audList = Array.isArray(payload.aud)
        ? payload.aud.map(value => (typeof value === "string" ? value.trim() : value))
        : typeof payload.aud === "string"
          ? [payload.aud.trim()]
          : [];
      const hasAudience = expectedAudience.some(expected => audList.includes(expected));
      if (!hasAudience) {
        throw new Error(`Missing required audience. Expected one of ${expectedAudience.join(", ")}, got ${audList.join(", ")}`);
      }
      console.log("[auth] token payload", JSON.stringify(payload, null, 2));
      const scopeField = payload.scope || payload.scp || "";
      const tokenScopes = Array.isArray(scopeField)
        ? scopeField
        : String(scopeField)
          .split(/\s+/)
          .filter(Boolean);
      const missing = requiredScopes.filter(scope => scope && !tokenScopes.includes(scope));
      if (missing.length) {
        throw new Error(`Missing required scopes: ${missing.join(", ")}`);
      }
      if (!payload.sub) {
        throw new Error("Token missing subject (sub) claim");
      }
      return { userKey: payload.sub, scopes: tokenScopes, payload };
    } catch (err) {
      console.error("[auth] token verification failed", err);
      sendUnauthorized(res, err.message || "Invalid token");
      return null;
    }
  }

  const fallback = requireUserKey(req, res);
  if (!fallback) return null;
  return { userKey: fallback, scopes: [] };
}

function requireAuth(handler) {
  return async (req, res, next) => {
    const authContext = await authenticateRequest(req, res);
    if (!authContext) return;
    req.authContext = authContext;
    return handler ? handler(req, res, next) : next();
  };
}

function resolveSessionUserKey(extra) {
  const sessionId = extra?.sessionId || extra?.requestInfo?.headers?.["mcp-session-id"];
  const userKey = getSessionUserKey(sessionId);
  if (!userKey) {
    throw new Error("Missing authenticated user for this MCP session. Ensure OAuth is configured and the connector completed sign-in.");
  }
  return userKey;
}

const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"), false);
  },
}));

const modulePath = fileURLToPath(import.meta.url);

const redisRestUrl = REDIS_REST_URL
  || process.env.UPSTASH_REDIS_REST_URL
  || process.env.KV_REST_API_URL;
const redisRestToken = REDIS_REST_TOKEN
  || process.env.UPSTASH_REDIS_REST_TOKEN
  || process.env.KV_REST_API_TOKEN;
const redisReadOnlyToken = process.env.KV_REST_API_READ_ONLY_TOKEN;

if (!redisRestToken && redisReadOnlyToken) {
  console.warn("[token-store] KV_REST_API_READ_ONLY_TOKEN is set, but write access requires KV_REST_API_TOKEN.");
}

if (!redisRestUrl || !redisRestToken) {
  throw new Error("Redis credentials are required. Provide REDIS_REST_URL/REDIS_REST_TOKEN, UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN, or KV_REST_API_URL/KV_REST_API_TOKEN.");
}

const tokenStore = createTokenStore({
  url: redisRestUrl,
  token: redisRestToken,
  namespace: REDIS_NAMESPACE,
});
console.log(`[token-store] driver=redis namespace=${REDIS_NAMESPACE}`);
const stateStore = new Map(); // key: state -> userKey

const oauth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

function yt(tokens) {
  oauth2Client.setCredentials(tokens);
  return google.youtube({ version: "v3", auth: oauth2Client });
}

async function getTokensOrThrow(userKey) {
  if (!userKey) throw new Error("Missing user key");
  const tokens = await tokenStore.get(userKey);
  if (!tokens) {
    throw new Error(`Not authorized yet. Visit ${publicBase}/auth/start?userKey=${encodeURIComponent(userKey)} to connect your Google account.`);
  }
  return tokens;
}

async function searchMusicVideos(tokens, { query, maxResults = 25 }) {
  const youtube = yt(tokens);
  const resp = await youtube.search.list({
    part: ["id", "snippet"],
    q: query,
    type: ["video"],
    maxResults: Math.min(Math.max(maxResults, 1), 50),
    topicId: "/m/04rlf",
  });

  return (resp.data.items || [])
    .map(i => ({
      videoId: i?.id?.videoId,
      title: i?.snippet?.title,
      channelTitle: i?.snippet?.channelTitle,
    }))
    .filter(v => v.videoId);
}

async function createPlaylist(tokens, { name, privacyStatus = "private", description = "" }) {
  const youtube = yt(tokens);
  const resp = await youtube.playlists.insert({
    part: ["snippet", "status"],
    requestBody: {
      snippet: { title: name, description },
      status: { privacyStatus },
    },
  });

  const id = resp.data.id;
  return { id, url: `https://www.youtube.com/playlist?list=${id}` };
}

async function addPlaylistItems(tokens, playlistId, videoIds) {
  const youtube = yt(tokens);
  const results = [];
  for (const videoId of videoIds) {
    const r = await youtube.playlistItems.insert({
      part: ["snippet"],
      requestBody: {
        snippet: {
          playlistId,
          resourceId: { kind: "youtube#video", videoId },
        },
      },
    });
    results.push(r.data.id);
  }
  return { added: results.length, itemIds: results };
}

/**
 * Dev helper: derive userKey from header/query when OAuth is disabled.
 */
function requireUserKey(req, res) {
  const key = req.header("X-User-Key") || req.query.userKey;
  if (!key) {
    res.status(400).json({ error: "Missing user key. Provide 'X-User-Key' header (preferred) or ?userKey=..." });
    return null;
  }
  return key;
}

async function getTokensOr401(req, res) {
  const userKey = req.authContext?.userKey || requireUserKey(req, res);
  if (!userKey) return [null, null];
  const tokens = await tokenStore.get(userKey);
  if (!tokens) {
    res.status(401).json({ error: `Not authorized with Google yet for this user. Visit ${publicBase}/auth/start?userKey=${encodeURIComponent(userKey)} to connect.` });
    return [null, null];
  }
  return [userKey, tokens];
}

// ---- OAuth: start the flow ----
app.get("/auth/start", (req, res) => {
  const userKey = req.query.userKey;
  if (!userKey) return res.status(400).send("Missing ?userKey=YOUR_KEY");

  const state = `${userKey}:${crypto.randomBytes(8).toString("hex")}`;
  stateStore.set(state, userKey);
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/youtube"],
    prompt: "consent",
    state,
  });
  res.redirect(url);
});

// ---- OAuth: callback ----
app.get("/oauth2/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state;
    if (!code || !state) return res.status(400).send("Missing code/state");
    const userKey = stateStore.get(state);
    if (!userKey) return res.status(400).send("Invalid state");

    const { tokens } = await oauth2Client.getToken(code);
    await tokenStore.set(userKey, tokens);
    stateStore.delete(state);

    res.send(`
      <html>
        <head><title>Connected</title></head>
        <body style="font-family: ui-sans-serif, system-ui">
          <h2>You're connected to YouTube for userKey: <code>${userKey}</code> 🎉</h2>
          <p>You can close this window and return to ChatGPT.</p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth error");
  }
});

// ---- API: search videos (music-biased) ----
app.get("/search", requireAuth(async (req, res) => {
  const [userKey, tokens] = await getTokensOr401(req, res);
  if (!tokens) return;
  try {
    const q = req.query.q;
    if (!q) return res.status(400).json({ error: "Missing query param q" });
    const items = await searchMusicVideos(tokens, {
      query: q,
      maxResults: clampMaxResults(req.query.max),
    });
    res.json({ items });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Search failed" });
  }
}));

// ---- API: create playlist ----
app.post("/playlists", requireAuth(async (req, res) => {
  const [userKey, tokens] = await getTokensOr401(req, res);
  if (!tokens) return;
  try {
    const { name, privacyStatus = "private", description = "" } = req.body || {};
    if (!name) return res.status(400).json({ error: "name is required" });
    const playlist = await createPlaylist(tokens, { name, privacyStatus, description });
    res.json(playlist);
  } catch (err) {
    console.error(err);
    const code = err?.errors?.[0]?.reason || "playlist_error";
    res.status(500).json({ error: "Playlist create failed", reason: code });
  }
}));

// ---- API: add items to playlist ----
app.post("/playlists/:id/items", requireAuth(async (req, res) => {
  const [userKey, tokens] = await getTokensOr401(req, res);
  if (!tokens) return;
  try {
    const id = req.params.id;
    const { videoIds } = req.body || {};
    if (!id || !Array.isArray(videoIds) || videoIds.length === 0) {
      return res.status(400).json({ error: "Provide :id and non-empty body.videoIds[]" });
    }
    const results = await addPlaylistItems(tokens, id, videoIds);
    res.json(results);
  } catch (err) {
    console.error(err);
    const code = err?.errors?.[0]?.reason || "insert_error";
    res.status(500).json({ error: "Insert failed", reason: code });
  }
}));

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "ytm-chatgpt-apps", endpoints: ["/auth/start?userKey=...", "/search", "/playlists", "/playlists/:id/items"] });
});

const openIdMetadata = oauthConfigured
  ? {
    issuer: AUTH_ISSUER,
    authorization_endpoint: AUTH_AUTHORIZATION_ENDPOINT || `${AUTH_ISSUER.replace(/\/$/, "")}/authorize`,
    token_endpoint: AUTH_TOKEN_ENDPOINT || `${AUTH_ISSUER.replace(/\/$/, "")}/oauth/token`,
    jwks_uri: AUTH_JWKS_URL,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: requiredScopes,
    ...(AUTH_REGISTRATION_ENDPOINT && { registration_endpoint: AUTH_REGISTRATION_ENDPOINT }),
  }
  : null;

function serveIfConfigured(res, payload) {
  if (!payload) {
    res.status(404).json({ error: "oauth_not_configured" });
    return false;
  }
  res.json(payload);
  return true;
}

const oauthProtectedRoutes = [
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/mcp",
];
oauthProtectedRoutes.forEach(path => {
  app.get(path, (_req, res) => {
    res.json({
      resource: resourceId,
      resource_uri: resourceId,
      scopes_supported: requiredScopes,
      authorization_servers: authServersForMetadata,
      bearer_methods_supported: ["authorization_header"],
      token_formats_supported: ["jwt"],
    });
  });
});

const openIdPaths = [
  "/.well-known/openid-configuration",
  "/.well-known/openid-configuration/mcp",
  "/mcp/.well-known/openid-configuration",
];
openIdPaths.forEach(path => {
  app.get(path, (_req, res) => {
    serveIfConfigured(res, openIdMetadata);
  });
});

const oauthServerPaths = [
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-authorization-server/mcp",
];
oauthServerPaths.forEach(path => {
  app.get(path, (_req, res) => {
    serveIfConfigured(res, openIdMetadata);
  });
});

// ---- MCP server (ChatGPT Apps SDK) ----
const mcpSessions = new Map();
const pendingMcpSessions = new Set();

const getSessionUserKey = sessionId => (sessionId ? mcpSessions.get(sessionId)?.userKey : undefined);

function storeMcpSession(context, sidOverride) {
  const sid = sidOverride || context.transport.sessionId;
  if (!sid) return;
  context.sessionId = sid;
  if (!mcpSessions.has(sid)) {
    mcpSessions.set(sid, context);
    pendingMcpSessions.delete(context);
    console.log(`[mcp] session ready ${sid}`);
  }
}

function createTransport() {
  return new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    enableJsonResponse: true,
    enableDnsRebindingProtection: allowedMcpHosts.length > 0 || allowedMcpOrigins.length > 0,
    allowedOrigins: allowedMcpOrigins.length ? allowedMcpOrigins : undefined,
    allowedHosts: allowedMcpHosts.length ? allowedMcpHosts : undefined,
  });
}

function createYouTubeMcpServer() {
  const server = new McpServer({
    name: "ytm-playlist-builder",
    version: "0.2.0",
    description: "Search music-biased YouTube results and manage playlists",
    websiteUrl: "https://github.com/sancerio/ytm-chatgpt-apps",
  }, { capabilities: { logging: {} } });

  server.registerTool("search_music_videos", {
    title: "Search Music Videos",
    description: "Find up to 50 music-biased YouTube videos",
    inputSchema: {
      query: z.string().min(1).describe("Free-form search query"),
      max: z.number().int().min(1).max(50).optional().describe("Maximum number of videos to return"),
    },
    outputSchema: {
      items: z.array(z.object({
        videoId: z.string(),
        title: z.string().optional(),
        channelTitle: z.string().optional(),
      })),
    },
  }, async ({ query, max }, extra) => {
    try {
      const userKey = resolveSessionUserKey(extra);
      const tokens = await getTokensOrThrow(userKey);
      const items = await searchMusicVideos(tokens, { query, maxResults: clampMaxResults(max) });
      return {
        content: [{ type: "text", text: `Found ${items.length} tracks for "${query}"` }],
        structuredContent: { items },
      };
    } catch (err) {
      return server.createToolError(err.message || "Search failed");
    }
  });

  server.registerTool("create_playlist", {
    title: "Create Playlist",
    description: "Create a playlist in the authorized YouTube channel",
    inputSchema: {
      name: z.string().min(1).describe("Playlist title"),
      description: z.string().optional().describe("Optional playlist description"),
      privacyStatus: z.enum(["private", "unlisted", "public"]).optional().describe("YouTube privacy status"),
    },
    outputSchema: {
      id: z.string(),
      url: z.string().url(),
    },
  }, async ({ name, description = "", privacyStatus = "private" }, extra) => {
    try {
      const userKey = resolveSessionUserKey(extra);
      const tokens = await getTokensOrThrow(userKey);
      const playlist = await createPlaylist(tokens, { name, description, privacyStatus });
      return {
        content: [{ type: "text", text: `Playlist ${name} created (${playlist.url})` }],
        structuredContent: playlist,
      };
    } catch (err) {
      return server.createToolError(err.message || "Playlist create failed");
    }
  });

  server.registerTool("add_videos_to_playlist", {
    title: "Add Videos To Playlist",
    description: "Insert one or more videos into a playlist",
    inputSchema: {
      playlistId: z.string().min(1).describe("Target playlist ID"),
      videoIds: z.array(z.string().min(1)).nonempty().describe("Array of YouTube video IDs"),
    },
    outputSchema: {
      added: z.number().int(),
      itemIds: z.array(z.string()),
    },
  }, async ({ playlistId, videoIds }, extra) => {
    try {
      const userKey = resolveSessionUserKey(extra);
      const tokens = await getTokensOrThrow(userKey);
      const result = await addPlaylistItems(tokens, playlistId, videoIds);
      return {
        content: [{ type: "text", text: `Added ${result.added} items to playlist ${playlistId}` }],
        structuredContent: result,
      };
    } catch (err) {
      return server.createToolError(err.message || "Insert failed");
    }
  });

  return server;
}

async function ensureSession(userKey) {
  const transport = createTransport();
  const server = createYouTubeMcpServer();
  const context = { transport, server, userKey };
  pendingMcpSessions.add(context);

  transport.onsessioninitialized = sid => {
    if (sid) {
      console.log(`[mcp] session initialized ${sid}`);
      storeMcpSession(context);
    }
  };
  transport.onclose = () => {
    const sid = transport.sessionId;
    if (sid) {
      console.log(`[mcp] session closed ${sid}`);
      mcpSessions.delete(sid);
    }
    pendingMcpSessions.delete(context);
  };
  transport.onerror = error => console.error("[mcp] transport error", error);

  await server.connect(transport);
  return context;
}

app.head("/mcp", (_req, res) => {
  res.sendStatus(204);
});

app.post("/mcp", async (req, res) => {
  const sessionId = req.header("mcp-session-id");
  const method = req.body?.method;
  console.log(`[mcp] POST method=${method || "unknown"} session=${sessionId || "<none>"}`);
  const authContext = await authenticateRequest(req, res);
  if (!authContext) return;
  try {
    let context = sessionId ? mcpSessions.get(sessionId) : null;
    if (!context) {
      if (!isInitializeRequest(req.body)) {
        return res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Initialization required" },
          id: null,
        });
      }
      context = await ensureSession(authContext.userKey);
    } else {
      context.userKey = authContext.userKey;
    }
    await context.transport.handleRequest(req, res, req.body);
    storeMcpSession(context);
  } catch (err) {
    console.error("[mcp] POST error", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal MCP error" },
        id: null,
      });
    }
  }
});

async function handleStreamableRequest(req, res) {
  const sessionId = req.header("mcp-session-id");
  const accept = req.headers.accept || "";
  const wantsEventStream = accept.includes("text/event-stream");
  const context = sessionId ? mcpSessions.get(sessionId) : null;
  console.log(`[mcp] ${req.method} stream session=${sessionId || "<none>"} accept=${accept || "<none>"}`);
  if (!context || !wantsEventStream) {
    res.status(200).json({
      ok: true,
      message: "MCP endpoint ready. POST initialize to begin a session.",
    });
    return;
  }
  const authContext = await authenticateRequest(req, res);
  if (!authContext) return;
  context.userKey = authContext.userKey;
  try {
    await context.transport.handleRequest(req, res);
  } catch (err) {
    console.error("[mcp] stream error", err);
    if (!res.headersSent) {
      res.status(500).end();
    }
  }
}

app.get("/mcp", handleStreamableRequest);
app.delete("/mcp", handleStreamableRequest);

const isDirectRun = process.argv[1] && resolve(process.argv[1]) === modulePath;

if (isDirectRun) {
  const { PORT = 3000 } = process.env;
  app.listen(PORT, () => {
    console.log(`[server] listening on http://localhost:${PORT}`);
  });
}

export default app;
