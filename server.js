// server.js
// A zero-cost, self-hosted livestream backend with Ethereum (MetaMask) authentication,
// session logging, health & metrics, and admin tools for user CRUD & key revocation

// Load environment variables
require('dotenv').config();
// DEBUG: log ADMIN_SECRET on startup
console.log('→ ADMIN_SECRET is:', process.env.ADMIN_SECRET);

// Dependencies
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { SiweMessage } = require('siwe');
const NodeMediaServer = require('node-media-server');
const bodyParser = require('body-parser');

// Environment
const MONGO_URI    = process.env.MONGO_URI    || 'mongodb://localhost:27017/livestream';
const EXPRESS_PORT = process.env.PORT         || 3001;
const JWT_SECRET   = process.env.JWT_SECRET   || crypto.randomBytes(32).toString('hex');
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

// 1. Connect to MongoDB
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// 2. Define User schema + model
const userSchema = new mongoose.Schema({
  ethAddress: { type: String, unique: true, required: true, lowercase: true },
  streamKey:  { type: String, unique: true, default: () => crypto.randomBytes(8).toString('hex') },
  disabled:   { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// 3. Define StreamSession schema + model
const sessionSchema = new mongoose.Schema({
  user:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  streamKey: { type: String, required: true },
  startedAt: { type: Date, default: Date.now },
  endedAt:   { type: Date, default: null }
});
const StreamSession = mongoose.model('StreamSession', sessionSchema);

// 4. Setup Express app
const app = express();
app.use(bodyParser.json());

// 5. In-memory store for SIWE nonces
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
    if (!nonces.has(data.nonce)) return res.status(401).json({ error: 'Invalid nonce' });
    nonces.delete(data.nonce);

    const address = data.address.toLowerCase();
    let user = await User.findOne({ ethAddress: address });
    if (!user) {
      user = new User({ ethAddress: address });
      await user.save();
    }
    if (user.disabled) return res.status(403).json({ error: 'Account disabled' });

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
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing Authorization' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.address = payload.address;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// 9. Admin auth middleware
const adminMiddleware = (req, res, next) => {
  const secret = req.header('X-Admin-Secret');
  if (!ADMIN_SECRET || secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

// 10. StreamKey endpoints
app.get('/streamKey', authMiddleware, async (req, res) => {
  const user = await User.findOne({ ethAddress: req.address });
  res.json({ streamKey: user.streamKey });
});
app.post('/streamKey/rotate', authMiddleware, async (req, res) => {
  const user = await User.findOne({ ethAddress: req.address });
  user.streamKey = crypto.randomBytes(8).toString('hex');
  await user.save();
  res.json({ streamKey: user.streamKey });
});

// 11. Streams discovery endpoints
app.get('/streams/active', async (req, res) => {
  const sessions = await StreamSession.find({ endedAt: null }).populate('user', 'ethAddress');
  res.json(sessions.map(s => ({ ethAddress: s.user.ethAddress, streamKey: s.streamKey, startedAt: s.startedAt })));
});
app.get('/streams/:streamKey/status', async (req, res) => {
  const session = await StreamSession.findOne({ streamKey: req.params.streamKey, endedAt: null });
  res.json(session ? { live: true, since: session.startedAt } : { live: false });
});

// 12. Health & metrics endpoints
app.get('/health', (req, res) => {
  const dbState = mongoose.connection.readyState === 1 ? 'up' : 'down';
  res.json({ database: dbState, uptime: process.uptime() });
});
app.get('/metrics', async (req, res) => {
  const today = new Date(); today.setHours(0,0,0,0);
  const totalUsers      = await User.countDocuments();
  const streamsToday    = await StreamSession.countDocuments({ startedAt: { $gte: today } });
  const endedSessions   = await StreamSession.find({ endedAt: { $gte: today } });
  const durations       = endedSessions.map(s => s.endedAt - s.startedAt);
  const avgDurationMs   = durations.length ? durations.reduce((a,b) => a+b,0)/durations.length : 0;
  res.json({ totalUsers, streamsToday, avgDurationMs });
});

// 13. Admin tools: user CRUD & key revocation
app.get('/admin/users', adminMiddleware, async (req, res) => {
  const users = await User.find().select('ethAddress streamKey disabled');
  res.json(users);
});
app.delete('/admin/users/:id', adminMiddleware, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { disabled: true });
  res.sendStatus(204);
});
app.post('/admin/users/:id/enable', adminMiddleware, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { disabled: false });
  res.sendStatus(200);
});
app.post('/admin/streamKey/revoke/:streamKey', adminMiddleware, async (req, res) => {
  const user = await User.findOne({ streamKey: req.params.streamKey });
  if (!user) return res.status(404).json({ error: 'Not found' });
  user.disabled = true;
  await user.save();
  res.json({ message: 'User disabled' });
});

// Start Express server
app.listen(EXPRESS_PORT, () => {
  console.log(`✅ Express running on port ${EXPRESS_PORT}`);
});

// 14. Node-Media-Server config
const nmsConfig = {
  rtmp:   { port: 1935, chunk_size: 60000, gop_cache: true, ping: 30, ping_timeout: 60 },
  http:   { port: 8000, allow_origin: '*' },
  trans:  { ffmpeg: '/usr/bin/ffmpeg', tasks: [{ app: 'live', hls: true, hlsFlags: '[hls_time=2:hls_list_size=3:hls_flags=delete_segments]', dash: false }] }
};

// 15. Instantiate & secure Node-Media-Server
const nms = new NodeMediaServer(nmsConfig);
nms.on('prePublish', async (id, StreamPath) => {
  const session = nms.getSession(id);
  const key     = StreamPath.split('/')[2];
  const user    = await User.findOne({ streamKey: key });
  if (!user || user.disabled) {
    console.warn(`🔒 Rejecting publish for key ${key}`);
    return session.reject();
  }
  const streamSession = new StreamSession({ user: user._id, streamKey: key });
  await streamSession.save();
  session.streamSessionId = streamSession._id;
});

nms.on('donePublish', async (id) => {
  const session = nms.getSession(id);
  if (session && session.streamSessionId) {
    await StreamSession.findByIdAndUpdate(session.streamSessionId, { endedAt: new Date() });
    console.log(`🛑 Stream session ${session.streamSessionId} ended`);
  }
});

nms.run();
