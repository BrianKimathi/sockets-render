import express from "express";
import http from "http";
import cors from "cors";
import { Server as SocketIOServer } from "socket.io";
import admin from "firebase-admin";

// Basic logger
const log = {
  info: (msg, meta = {}) => console.log(`[INFO] ${msg}`, meta),
  warn: (msg, meta = {}) => console.warn(`[WARN] ${msg}`, meta),
  error: (msg, meta = {}) => console.error(`[ERROR] ${msg}`, meta),
  debug: (msg, meta = {}) => console.debug(`[DEBUG] ${msg}`, meta),
};

// Env
const PORT = process.env.PORT || 10000;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const INTERNAL_EMIT_SECRET = process.env.INTERNAL_EMIT_SECRET || "";

// Firebase Admin init (optional, used to verify client tokens)
if (!admin.apps.length) {
  try {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = (process.env.FIREBASE_PRIVATE_KEY || "").replace(
      /\\n/g,
      "\n"
    );

    if (projectId && clientEmail && privateKey) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey,
        }),
        databaseURL: process.env.FIREBASE_DATABASE_URL,
      });
      log.info("Firebase Admin initialized");
    } else {
      log.warn(
        "Firebase Admin not fully configured; client token verification will be skipped"
      );
    }
  } catch (e) {
    log.error("Failed to initialize Firebase Admin", { error: e.message });
  }
}

const app = express();
const server = http.createServer(app);

// CORS
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (ALLOWED_ORIGINS.length === 0) return callback(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "ngrok-skip-browser-warning",
      "X-Internal-Secret",
    ],
    methods: ["GET", "POST", "OPTIONS"],
  })
);
app.use(express.json({ limit: "1mb" }));

// Socket.IO
const io = new SocketIOServer(server, {
  cors: {
    origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true,
    credentials: true,
    allowedHeaders: ["Authorization", "ngrok-skip-browser-warning"],
  },
  transports: ["polling", "websocket"],
  allowEIO3: true,
  pingTimeout: 25000,
  pingInterval: 10000,
  maxHttpBufferSize: 1e6,
});

// Verify Firebase token helper (optional)
async function verifyIdTokenMaybe(idToken) {
  if (!idToken || !admin.apps.length) return null;
  try {
    return await admin.auth().verifyIdToken(idToken);
  } catch (e) {
    log.warn("Invalid Firebase token", { error: e.message });
    return null;
  }
}

io.on("connection", async (socket) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    const providedUid = socket.handshake.auth && socket.handshake.auth.uid;
    const decoded = await verifyIdTokenMaybe(token);
    const userId = decoded?.uid || providedUid || null;

    if (!userId) {
      // Allow anonymous connect but do not join user room
      log.warn("Socket connected without verified user; limited capabilities", {
        sid: socket.id,
      });
    } else {
      const userRoom = `user:${userId}`;
      socket.join(userRoom);
      log.info("Client joined user room", {
        userId,
        room: userRoom,
        sid: socket.id,
      });
    }

    socket.on("join:challenge", ({ challengeId }) => {
      if (!challengeId) return;
      const room = `challenge:${challengeId}`;
      socket.join(room);
      log.debug("Client joined challenge room", { room, sid: socket.id });
    });

    socket.on("leave:challenge", ({ challengeId }) => {
      if (!challengeId) return;
      const room = `challenge:${challengeId}`;
      socket.leave(room);
      log.debug("Client left challenge room", { room, sid: socket.id });
    });

    socket.on("disconnect", (reason) => {
      log.info("Socket disconnected", { sid: socket.id, reason });
    });
  } catch (e) {
    log.error("Socket connection handler error", { error: e.message });
  }
});

// Internal auth middleware for emit endpoints
function requireInternalSecret(req, res, next) {
  const header = req.header("X-Internal-Secret") || "";
  if (!INTERNAL_EMIT_SECRET || header !== INTERNAL_EMIT_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Emit helpers
function emitChallengeCreated(challengerId, challengedId, payload) {
  io.to(`user:${challengedId}`).emit("challenge:created", payload);
  io.to(`user:${challengerId}`).emit("challenge:created", payload);
}

function emitChallengeAccepted(challengerId, challengedId, payload) {
  io.to(`user:${challengerId}`).emit("challenge:accepted", payload);
  io.to(`user:${challengedId}`).emit("challenge:accepted", payload);
}

function emitChallengeRejected(challengerId, challengedId, payload) {
  io.to(`user:${challengerId}`).emit("challenge:rejected", payload);
  io.to(`user:${challengedId}`).emit("challenge:rejected", payload);
}

function emitScoreUpdated(userId, opponentId, challengeId, payload) {
  const enriched = { challengeId, userId, ...payload };
  io.to(`user:${opponentId}`).emit("challenge:score_updated", enriched);
  io.to(`user:${userId}`).emit("challenge:score_updated", enriched);
  io.to(`challenge:${challengeId}`).emit("challenge:score_updated", enriched);
}

function emitChallengeCompleted(challengerId, challengedId, payload) {
  io.to(`user:${challengerId}`).emit("challenge:completed", payload);
  io.to(`user:${challengedId}`).emit("challenge:completed", payload);
}

// Internal emit routes
app.post("/emit/challenge-created", requireInternalSecret, (req, res) => {
  const { challengerId, challengedId, data } = req.body || {};
  if (!challengerId || !challengedId || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitChallengeCreated(challengerId, challengedId, data);
  return res.json({ ok: true });
});

app.post("/emit/challenge-accepted", requireInternalSecret, (req, res) => {
  const { challengerId, challengedId, data } = req.body || {};
  if (!challengerId || !challengedId || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitChallengeAccepted(challengerId, challengedId, data);
  return res.json({ ok: true });
});

app.post("/emit/challenge-rejected", requireInternalSecret, (req, res) => {
  const { challengerId, challengedId, data } = req.body || {};
  if (!challengerId || !challengedId || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitChallengeRejected(challengerId, challengedId, data);
  return res.json({ ok: true });
});

app.post("/emit/score-updated", requireInternalSecret, (req, res) => {
  const { userId, opponentId, challengeId, data } = req.body || {};
  if (!userId || !opponentId || !challengeId || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitScoreUpdated(userId, opponentId, challengeId, data);
  return res.json({ ok: true });
});

app.post("/emit/challenge-completed", requireInternalSecret, (req, res) => {
  const { challengerId, challengedId, data } = req.body || {};
  if (!challengerId || !challengedId || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitChallengeCompleted(challengerId, challengedId, data);
  return res.json({ ok: true });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

server.listen(PORT, () => {
  log.info("Sockets service listening", { port: PORT });
});
