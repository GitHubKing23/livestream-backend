// server.js
// A zero-cost, self-hosted livestream backend with Ethereum (MetaMask) authentication
// and session logging for active-streams discovery

// Load environment variables
require('dotenv').config();

// Dependencies
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { SiweMessage } = require('siwe');
const NodeMediaServer = require('node-media-server');
const bodyParser = require('body-parser');

// Environment
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/livestream';
const EXPRESS_PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// 1. Connect to MongoDB
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// 2. Define User schema + model (using Ethereum address)
const userSchema = new mongoose.Schema({
  ethAddress: { type: String, unique: true, required: true, lowercase: true },
  streamKey: { type: String, unique: true, default: () => crypto.randomBytes(8).toString('hex') }
});
const User = mongoose.model('User', userSchema);

// 3. Define StreamSession schema + model
const sessionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  streamKey: { type: String, required: true },
  startedAt: { type: Date, default: Date.now },
  endedAt: { type: Date, default: null }
});
const StreamSession = mongoose.model('StreamSession', sessionSchema);

// 4. Setup Express app
const app = express();
app.use(bodyParser.json());

// 5. In-memory store for SIWE nonces (for production, use Redis or DB)
const nonces = new Set();

// 6. SIWE: Generate a nonce
app.get('/siwe/nonce', (req, res) => {
  const nonce = crypto.randomBytes(16).toString('hex');
  nonces.add(nonce);
  res.type('text/plain').send(nonce);
});

// 7. SIWE: Verify signature and issue JWT + return streamKey
app.post('/siwe/verify', async (req, res) => {
  try {
    const { message, signature } = req.body;
    const siweMessage = new SiweMessage(message);
    const { data } = await siweMessage.validate(signature);

    // Validate nonce
    if (!nonces.has(data.nonce)) {
      return res.status(401).json({ error: 'Invalid nonce' });
    }
    nonces.delete(data.nonce);

    const address = data.address.toLowerCase();
    let user = await User.findOne({ ethAddress: address });
    if (!user) {
      user = new User({ ethAddress: address });
      await user.save();
    }

    // Issue JWT
    const token = jwt.sign({ address }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ address, streamKey: user.streamKey, token });
  } catch (e) {
    console.error('SIWE verify error:', e);
    res.status(401).json({ error: 'Signature verification failed' });
  }
});

// 8. Auth middleware for Ethereum JWT
const authMiddleware = (req, res, next) => {
  const auth = req.header('Authorization') || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.address = payload.address;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// 9. StreamKey endpoints
// Get current streamKey
app.get('/streamKey', authMiddleware, async (req, res) => {
  const address = req.address;
  const user = await User.findOne({ ethAddress: address });
  res.json({ streamKey: user.streamKey });
});

// Rotate streamKey
app.post('/streamKey/rotate', authMiddleware, async (req, res) => {
  const address = req.address;
  const user = await User.findOne({ ethAddress: address });
  user.streamKey = crypto.randomBytes(8).toString('hex');
  await user.save();
  res.json({ streamKey: user.streamKey });
});

// 10. Streams discovery endpoints
// List active streams
app.get('/streams/active', async (req, res) => {
  const sessions = await StreamSession.find({ endedAt: null }).populate('user', 'ethAddress');
  const active = sessions.map(s => ({
    ethAddress: s.user.ethAddress,
    streamKey: s.streamKey,
    startedAt: s.startedAt
  }));
  res.json(active);
});

// Stream status by key
app.get('/streams/:streamKey/status', async (req, res) => {
  const { streamKey } = req.params;
  const session = await StreamSession.findOne({ streamKey, endedAt: null });
  if (session) {
    res.json({ live: true, since: session.startedAt });
  } else {
    res.json({ live: false });
  }
});

// 11. Health check endpoint
app.get('/health', async (req, res) => {
  const dbState = mongoose.connection.readyState === 1 ? 'up' : 'down';
  res.json({ database: dbState, uptime: process.uptime() });
});

// Start Express server
app.listen(EXPRESS_PORT, () => {
  console.log(`✅ Express running on port ${EXPRESS_PORT}`);
});

// 12. Node-Media-Server config
const nmsConfig = {
  rtmp: {
    port: 1935,
    chunk_size: 60000,
    gop_cache: true,
    ping: 30,
    ping_timeout: 60
  },
  http: {
    port: 8000,
    allow_origin: '*'
  },
  trans: {
    ffmpeg: '/usr/bin/ffmpeg',
    tasks: [
      {
        app: 'live',
        hls: true,
        hlsFlags: '[hls_time=2:hls_list_size=3:hls_flags=delete_segments]',
        dash: false
      }
    ]
  }
};

// 13. Instantiate & secure Node-Media-Server
const nms = new NodeMediaServer(nmsConfig);

// Store session IDs for mapping
nms.on('prePublish', async (id, StreamPath) => {
  const session = nms.getSession(id);
  const [, , key] = StreamPath.split('/');
  const user = await User.findOne({ streamKey: key });
  if (!user) {
    console.warn(`🔒 Rejecting publish: invalid key ${key}`);
    return session.reject();
  }
  console.log(`✅ Publishing allowed for ${user.ethAddress}`);

  // Log session start
  const streamSession = new StreamSession({ user: user._id, streamKey: key });
  await streamSession.save();
  session.streamSessionId = streamSession._id;
});

// On stream end, mark session ended
nms.on('donePublish', async (id, StreamPath) => {
  const session = nms.getSession(id);
  if (session && session.streamSessionId) {
    await StreamSession.findByIdAndUpdate(session.streamSessionId, { endedAt: new Date() });
    console.log(`🛑 Stream session ${session.streamSessionId} ended`);
  }
});

nms.run();
