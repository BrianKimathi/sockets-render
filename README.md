Sockets service for Render (Socket.IO)

Overview
This service provides Socket.IO real-time updates for the app when the main API is hosted on Vercel (which does not support persistent sockets). Deploy this service on Render and point clients to it.

Features
- Socket.IO server with polling+websocket
- Firebase ID token verification for clients (optional if service account envs set)
- User rooms (user:{uid}) and challenge rooms (challenge:{id})
- Internal REST endpoints to trigger emits from the API (secured with X-Internal-Secret)

Environment Variables
- PORT: assigned by Render
- ALLOWED_ORIGINS: comma-separated list of web/app origins
- INTERNAL_EMIT_SECRET: shared secret to authorize internal emit routes
- FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_DATABASE_URL: enable Firebase Admin for token verification

Deploy on Render
1) Create a new Web Service
   - Build Command: (leave blank for Node)
   - Start Command: node index.js
   - Root Directory: sockets-render
2) Set environment variables as above.
3) After deploy, note the service URL, e.g., https://your-sockets.onrender.com

Client Configuration
- Frontend (.env): VITE_SOCKET_URL=https://your-sockets.onrender.com
- Flutter: set socket base URL to https://your-sockets.onrender.com

Backend Configuration (Vercel API)
- Set SOCKETS_EMIT_URL=https://your-sockets.onrender.com
- Set SOCKETS_INTERNAL_SECRET to the same value as INTERNAL_EMIT_SECRET
- On events, the backend will POST to /emit/* endpoints to notify clients


