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
      socket.userId = userId; // Store for disconnect handler
      log.info("Client joined user room", {
        userId,
        room: userRoom,
        sid: socket.id,
      });
      
      // Emit online status globally (for direct chats)
      socket.broadcast.emit("user:online", {
        userId,
        online: true,
        timestamp: Date.now(),
      });
      log.info("🌐 Emitted global user:online", { userId, sid: socket.id });
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

    // Chat room events
    socket.on("join:chat", ({ chatId, chatType }) => {
      if (!chatId || !userId) {
        log.warn("join:chat: Missing chatId or userId", { chatId, userId, sid: socket.id });
        return;
      }
      const room = `chat:${chatType}:${chatId}`;
      socket.join(room);
      log.info("🔌 Client joined chat room", { 
        room, 
        chatId, 
        chatType, 
        userId, 
        sid: socket.id 
      });
      
      // Use setTimeout to ensure room is fully registered before checking
      setTimeout(() => {
        // Get list of online users in this room (after join is complete)
        const roomSockets = io.sockets.adapter.rooms.get(room);
        log.info("👥 Room sockets check", { 
          room, 
          chatId,
          roomExists: !!roomSockets, 
          socketCount: roomSockets ? roomSockets.size : 0 
        });
        
        if (roomSockets && roomSockets.size > 0) {
          const onlineUserIds = new Set();
          roomSockets.forEach((socketId) => {
            const socketInRoom = io.sockets.sockets.get(socketId);
            if (socketInRoom && socketInRoom.userId) {
              // Include all users in room (including self for initial list)
              onlineUserIds.add(socketInRoom.userId);
              log.debug("👤 Found user in room", { 
                socketId, 
                userId: socketInRoom.userId,
                isSelf: socketInRoom.userId === userId
              });
            }
          });
          
          log.info("📊 Online users in room", { 
            room, 
            chatId, 
            totalUsers: onlineUserIds.size, 
            userIds: Array.from(onlineUserIds) 
          });
          
          // Send list of online users to the joining user (excluding self)
          const otherUsers = Array.from(onlineUserIds).filter(id => id !== userId);
          socket.emit("chat:users:online", {
            chatId,
            chatType,
            userIds: otherUsers,
          });
          log.info("📤 Sent online users list", { 
            chatId, 
            recipient: userId, 
            onlineCount: otherUsers.length,
            userIds: otherUsers 
          });
        } else {
          log.warn("⚠️ No sockets found in room", { room, chatId });
          // Still send empty list so frontend knows room is empty
          socket.emit("chat:users:online", {
            chatId,
            chatType,
            userIds: [],
          });
        }
      }, 100); // Small delay to ensure room registration
      
      // Emit user online status to this specific chat room (to other users)
      socket.to(room).emit("user:online", {
        userId,
        online: true,
        timestamp: Date.now(),
        chatId,
        chatType,
      });
      log.info("📢 Emitted user:online to room", { 
        room, 
        userId, 
        chatId
      });
    });

    socket.on("leave:chat", ({ chatId, chatType }) => {
      if (!chatId || !userId) {
        log.warn("leave:chat: Missing chatId or userId", { chatId, userId, sid: socket.id });
        return;
      }
      const room = `chat:${chatType}:${chatId}`;
      
      // Emit user offline status to this specific chat room before leaving
      socket.to(room).emit("user:offline", {
        userId,
        online: false,
        timestamp: Date.now(),
        chatId,
        chatType,
      });
      log.info("📢 Emitted user:offline to room", { 
        room, 
        userId, 
        chatId,
        sid: socket.id 
      });
      
      socket.leave(room);
      log.info("🔌 Client left chat room", { room, chatId, userId, sid: socket.id });
    });

    // Typing indicator events
    socket.on("chat:typing:start", ({ chatId, chatType, userId, userName }) => {
      if (!chatId || !userId) return;
      const room = `chat:${chatType}:${chatId}`;
      socket.to(room).emit("chat:typing", {
        chatId,
        chatType,
        userId,
        userName,
        isTyping: true,
      });
      log.debug("Typing started", { room, userId, sid: socket.id });
    });

    socket.on("chat:typing:stop", ({ chatId, chatType, userId }) => {
      if (!chatId || !userId) return;
      const room = `chat:${chatType}:${chatId}`;
      socket.to(room).emit("chat:typing", {
        chatId,
        chatType,
        userId,
        isTyping: false,
      });
      log.debug("Typing stopped", { room, userId, sid: socket.id });
    });

    // Game playing events
    socket.on(
      "chat:game:playing",
      ({ chatId, chatType, userId, userName, gameTitle, gameId }) => {
        if (!chatId || !userId || !gameTitle) return;
        const room = `chat:${chatType}:${chatId}`;
        socket.to(room).emit("chat:game:playing", {
          chatId,
          chatType,
          userId,
          userName,
          gameTitle,
          gameId,
          isPlaying: true,
        });
        log.debug("Game playing", { room, userId, gameTitle, sid: socket.id });
      }
    );

    socket.on("chat:game:stopped", ({ chatId, chatType, userId }) => {
      if (!chatId || !userId) return;
      const room = `chat:${chatType}:${chatId}`;
      socket.to(room).emit("chat:game:playing", {
        chatId,
        chatType,
        userId,
        isPlaying: false,
      });
      log.debug("Game stopped", { room, userId, sid: socket.id });
    });

    // Game score events
    socket.on(
      "chat:game:score",
      ({ chatId, chatType, userId, userName, gameTitle, score }) => {
        if (!chatId || !userId || score === undefined) return;
        const room = `chat:${chatType}:${chatId}`;
        socket.to(room).emit("chat:game:score", {
          chatId,
          chatType,
          userId,
          userName,
          gameTitle,
          score,
          timestamp: Date.now(),
        });
        log.debug("Game score", {
          room,
          userId,
          gameTitle,
          score,
          sid: socket.id,
        });
      }
    );

    // Chat message events (direct and group)
    socket.on("chat:message", ({ chatId, chatType, messageId, senderId, senderName, senderAvatar, content, receiverId, timestamp, attachmentType }) => {
      if (!chatId || !senderId || !content) return;
      const room = `chat:${chatType}:${chatId}`;
      
      // Emit to all users in the chat room (except sender)
      socket.to(room).emit("chat:message", {
        chatId,
        chatType,
        messageId: messageId || `msg_${Date.now()}_${senderId}`,
        senderId,
        senderName: senderName || "User",
        senderAvatar: senderAvatar || "",
        content,
        receiverId,
        timestamp: timestamp || Date.now(),
        attachmentType: attachmentType || null,
      });
      
      // Also emit to receiver's user room for direct chats (in case they're not in the chat room)
      if (chatType === "direct" && receiverId) {
        socket.to(`user:${receiverId}`).emit("chat:message", {
          chatId,
          chatType,
          messageId: messageId || `msg_${Date.now()}_${senderId}`,
          senderId,
          senderName: senderName || "User",
          senderAvatar: senderAvatar || "",
          content,
          receiverId,
          timestamp: timestamp || Date.now(),
          attachmentType: attachmentType || null,
        });
      }
      
      log.debug("Chat message", { room, senderId, receiverId, chatType, sid: socket.id });
    });

    // Message status events (read receipts, delivered)
    socket.on("chat:message:read", ({ chatId, chatType, messageId, userId }) => {
      if (!chatId || !messageId || !userId) return;
      const room = `chat:${chatType}:${chatId}`;
      socket.to(room).emit("chat:message:read", {
        chatId,
        chatType,
        messageId,
        userId,
        readAt: Date.now(),
      });
      log.debug("Message read", { room, messageId, userId, sid: socket.id });
    });

    socket.on("chat:message:delivered", ({ chatId, chatType, messageId, userId }) => {
      if (!chatId || !messageId || !userId) return;
      const room = `chat:${chatType}:${chatId}`;
      socket.to(room).emit("chat:message:delivered", {
        chatId,
        chatType,
        messageId,
        userId,
        deliveredAt: Date.now(),
      });
      log.debug("Message delivered", { room, messageId, userId, sid: socket.id });
    });

    socket.on("disconnect", (reason) => {
      log.info("🔌 Socket disconnected", { sid: socket.id, userId, reason });
      // Emit offline status globally
      if (userId) {
        socket.broadcast.emit("user:offline", {
          userId,
          online: false,
          timestamp: Date.now(),
        });
        log.info("🌐 Emitted global user:offline", { userId, sid: socket.id });
      }
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

function emitChallengeCancelled(challengerId, challengedId, payload) {
  const enriched = { type: payload.type || "challenge_cancelled", ...payload };
  io.to(`user:${challengerId}`).emit("challenge:cancelled", enriched);
  io.to(`user:${challengedId}`).emit("challenge:cancelled", enriched);
  if (payload.challengeId) {
    io.to(`challenge:${payload.challengeId}`).emit(
      "challenge:cancelled",
      enriched
    );
  }
}

function emitChallengeReaction(challengeId, userId, reaction, payload) {
  const enriched = { challengeId, userId, reaction, ...payload };
  io.to(`challenge:${challengeId}`).emit("challenge:reaction", enriched);
  io.to(`user:${userId}`).emit("challenge:reaction", enriched);
  if (payload.opponentId) {
    io.to(`user:${payload.opponentId}`).emit("challenge:reaction", enriched);
  }
}

function emitChallengeMessage(challengeId, userId, message, payload) {
  const enriched = { challengeId, userId, message, ...payload };
  io.to(`challenge:${challengeId}`).emit("challenge:message", enriched);
  io.to(`user:${userId}`).emit("challenge:message", enriched);
  if (payload.opponentId) {
    io.to(`user:${payload.opponentId}`).emit("challenge:message", enriched);
  }
}

function emitChallengeGameStarted(
  userId,
  opponentId,
  challengeId,
  payload = {}
) {
  const enriched = {
    challengeId,
    userId,
    type: payload.type || "game_started",
    ...payload,
  };
  if (opponentId) {
    io.to(`user:${opponentId}`).emit("challenge:game_started", enriched);
  }
  if (userId) {
    io.to(`user:${userId}`).emit("challenge:game_started", enriched);
  }
  if (challengeId) {
    io.to(`challenge:${challengeId}`).emit("challenge:game_started", enriched);
  }
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

app.post("/emit/challenge-cancelled", requireInternalSecret, (req, res) => {
  const { challengerId, challengedId, data } = req.body || {};
  if (!challengerId || !challengedId || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitChallengeCancelled(challengerId, challengedId, data);
  return res.json({ ok: true });
});

app.post("/emit/challenge-reaction", requireInternalSecret, (req, res) => {
  const { challengeId, userId, opponentId, reaction, data } = req.body || {};
  if (!challengeId || !userId || !reaction || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitChallengeReaction(challengeId, userId, reaction, { ...data, opponentId });
  return res.json({ ok: true });
});

app.post("/emit/challenge-message", requireInternalSecret, (req, res) => {
  const { challengeId, userId, opponentId, message, data } = req.body || {};
  if (!challengeId || !userId || !message || !data)
    return res.status(400).json({ error: "Missing fields" });
  emitChallengeMessage(challengeId, userId, message, { ...data, opponentId });
  return res.json({ ok: true });
});

app.post("/emit/challenge-game-started", requireInternalSecret, (req, res) => {
  const { userId, opponentId, challengeId, data } = req.body || {};
  if (!userId || !opponentId || !challengeId) {
    return res.status(400).json({ error: "Missing fields" });
  }
  emitChallengeGameStarted(userId, opponentId, challengeId, data || {});
  return res.json({ ok: true });
});

// Chat emit helpers
function emitChatTyping(chatId, chatType, userId, userName, isTyping) {
  const room = `chat:${chatType}:${chatId}`;
  io.to(room).emit("chat:typing", {
    chatId,
    chatType,
    userId,
    userName,
    isTyping,
  });
}

function emitChatGamePlaying(
  chatId,
  chatType,
  userId,
  userName,
  gameTitle,
  gameId,
  isPlaying
) {
  const room = `chat:${chatType}:${chatId}`;
  io.to(room).emit("chat:game:playing", {
    chatId,
    chatType,
    userId,
    userName,
    gameTitle,
    gameId,
    isPlaying,
  });
}

function emitChatGameScore(
  chatId,
  chatType,
  userId,
  userName,
  gameTitle,
  score
) {
  const room = `chat:${chatType}:${chatId}`;
  io.to(room).emit("chat:game:score", {
    chatId,
    chatType,
    userId,
    userName,
    gameTitle,
    score,
    timestamp: Date.now(),
  });
}

// Internal emit routes for chat
app.post("/emit/chat-typing", requireInternalSecret, (req, res) => {
  const { chatId, chatType, userId, userName, isTyping } = req.body || {};
  if (!chatId || !chatType || !userId || isTyping === undefined) {
    return res.status(400).json({ error: "Missing fields" });
  }
  emitChatTyping(chatId, chatType, userId, userName, isTyping);
  return res.json({ ok: true });
});

app.post("/emit/chat-game-playing", requireInternalSecret, (req, res) => {
  const { chatId, chatType, userId, userName, gameTitle, gameId, isPlaying } =
    req.body || {};
  if (!chatId || !chatType || !userId || isPlaying === undefined) {
    return res.status(400).json({ error: "Missing fields" });
  }
  emitChatGamePlaying(
    chatId,
    chatType,
    userId,
    userName,
    gameTitle,
    gameId,
    isPlaying
  );
  return res.json({ ok: true });
});

app.post("/emit/chat-game-score", requireInternalSecret, (req, res) => {
  const { chatId, chatType, userId, userName, gameTitle, score } =
    req.body || {};
  if (!chatId || !chatType || !userId || score === undefined) {
    return res.status(400).json({ error: "Missing fields" });
  }
  emitChatGameScore(chatId, chatType, userId, userName, gameTitle, score);
  return res.json({ ok: true });
});

// Message status emit helpers
function emitMessageRead(chatId, chatType, messageId, userId) {
  const room = `chat:${chatType}:${chatId}`;
  io.to(room).emit("chat:message:read", {
    chatId,
    chatType,
    messageId,
    userId,
    readAt: Date.now(),
  });
}

function emitMessageDelivered(chatId, chatType, messageId, userId) {
  const room = `chat:${chatType}:${chatId}`;
  io.to(room).emit("chat:message:delivered", {
    chatId,
    chatType,
    messageId,
    userId,
    deliveredAt: Date.now(),
  });
}

app.post("/emit/chat-message-read", requireInternalSecret, (req, res) => {
  const { chatId, chatType, messageId, userId } = req.body || {};
  if (!chatId || !chatType || !messageId || !userId) {
    return res.status(400).json({ error: "Missing fields" });
  }
  emitMessageRead(chatId, chatType, messageId, userId);
  return res.json({ ok: true });
});

app.post("/emit/chat-message-delivered", requireInternalSecret, (req, res) => {
  const { chatId, chatType, messageId, userId } = req.body || {};
  if (!chatId || !chatType || !messageId || !userId) {
    return res.status(400).json({ error: "Missing fields" });
  }
  emitMessageDelivered(chatId, chatType, messageId, userId);
  return res.json({ ok: true });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

server.listen(PORT, () => {
  log.info("Sockets service listening", { port: PORT });
});
