require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 5000;

// ── Connect MongoDB ──────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB Connected!");
    autoSeed();
  })
  .catch(err => {
    console.error("MongoDB Failed:", err.message);
    process.exit(1);
  });

// ── Auto Seed Admin ──────────────────────
async function autoSeed() {
  try {
    const db = mongoose.connection.db;

    const existing = await db.collection("users").findOne({ email: "admin@firewall.io" });
    if (!existing) {
      const hash = await bcrypt.hash("Admin123", 12);
      await db.collection("users").insertOne({
        username: "admin",
        email: "admin@firewall.io",
        password: hash,
        role: "admin",
        isActive: true,
        loginAttempts: 0,
        createdAt: new Date()
      });
      console.log("Admin created: admin@firewall.io / Admin123");
    }

    const count = await db.collection("firewallrules").countDocuments();
    if (count === 0) {
      await db.collection("firewallrules").insertMany([
        { type: "ip_block", value: "10.10.10.10", action: "block", reason: "Demo blocked IP", isActive: true, priority: 150, hitCount: 0, createdAt: new Date() },
        { type: "ip_block", value: "192.0.2.1", action: "block", reason: "Known malicious IP", isActive: true, priority: 150, hitCount: 0, createdAt: new Date() },
        { type: "domain_block", value: "malicious.com", action: "block", reason: "Malware C2", isActive: true, priority: 150, hitCount: 0, createdAt: new Date() },
        { type: "domain_block", value: "phishing.net", action: "block", reason: "Phishing domain", isActive: true, priority: 150, hitCount: 0, createdAt: new Date() }
      ]);
      console.log("Sample rules created");
    }
  } catch (err) {
    console.error("Seed error:", err.message);
  }
}

// ── Middleware ───────────────────────────
app.use(helmet({ crossOriginEmbedderPolicy: false, contentSecurityPolicy: false }));
app.use(cors({ origin: "*", methods: ["GET","POST","PUT","DELETE","PATCH","OPTIONS"], allowedHeaders: ["Content-Type","Authorization"] }));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(rateLimit({ windowMs: 60000, max: 300, standardHeaders: true, legacyHeaders: false }));

// ── Models ───────────────────────────────
const UserSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: { type: String, select: false },
  role: { type: String, default: "user" },
  isActive: { type: Boolean, default: true },
  loginAttempts: { type: Number, default: 0 },
  lockedUntil: Date,
  lastLogin: Date
}, { timestamps: true });

const RuleSchema = new mongoose.Schema({
  type: String,
  value: String,
  action: { type: String, default: "block" },
  reason: String,
  isActive: { type: Boolean, default: true },
  priority: { type: Number, default: 100 },
  hitCount: { type: Number, default: 0 },
  lastTriggered: Date,
  createdBy: mongoose.Schema.Types.ObjectId
}, { timestamps: true });

const LogSchema = new mongoose.Schema({
  ip: String,
  method: String,
  endpoint: String,
  host: String,
  userAgent: String,
  status: { type: String, default: "allowed" },
  statusCode: Number,
  responseTime: Number,
  blockedReason: String,
  isAnomaly: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});

const AlertSchema = new mongoose.Schema({
  type: String,
  severity: { type: String, default: "medium" },
  ip: String,
  description: String,
  metadata: Object,
  isResolved: { type: Boolean, default: false },
  resolvedAt: Date,
  autoBlocked: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);
const Rule = mongoose.model("FirewallRule", RuleSchema);
const Log = mongoose.model("RequestLog", LogSchema);
const Alert = mongoose.model("Alert", AlertSchema);

// ── JWT Helper ───────────────────────────
const jwt = require("jsonwebtoken");
const SECRET = process.env.JWT_SECRET || "fallbacksecret123456789";

function genToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: "24h" });
}

function verifyToken(token) {
  return jwt.verify(token, SECRET);
}

// ── Auth Middleware ──────────────────────
async function protect(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ success: false, message: "No token" });
    const decoded = verifyToken(auth.split(" ")[1]);
    const user = await User.findById(decoded.id);
    if (!user || !user.isActive) return res.status(401).json({ success: false, message: "Invalid token" });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ success: false, message: "Token invalid or expired" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Admin only" });
  next();
}

// ── Anomaly Detection ────────────────────
const ipWindows = new Map();
const ipEndpoints = new Map();
const failedLogins = new Map();

function cleanOld(arr, seconds) {
  const cutoff = Date.now() - seconds * 1000;
  return arr.filter(t => t > cutoff);
}

async function detectAnomaly(ip, endpoint, userAgent) {
  const now = Date.now();

  if (!ipWindows.has(ip)) ipWindows.set(ip, []);
  let times = cleanOld(ipWindows.get(ip), 60);
  times.push(now);
  ipWindows.set(ip, times);

  if (!ipEndpoints.has(ip)) ipEndpoints.set(ip, new Set());
  ipEndpoints.get(ip).add(endpoint);

  const burst = cleanOld(times, 10);
  if (burst.length >= 20) {
    const severity = burst.length >= 50 ? "critical" : "high";
    await saveAlert("burst_traffic", severity, ip, `Burst: ${burst.length} requests in 10s`, { requestCount: burst.length }, userAgent);
    return { block: severity === "critical", type: "burst_traffic", severity };
  }

  if (ipEndpoints.get(ip).size >= 15) {
    await saveAlert("port_scan", "high", ip, `Port scan: ${ipEndpoints.get(ip).size} endpoints`, {}, userAgent);
    return { block: false, type: "port_scan", severity: "high" };
  }

  const bad = [/union.*select/i, /<script/i, /\.\.\//,  /exec\s*\(/i, /etc\/passwd/i];
  if (bad.some(p => p.test(endpoint))) {
    await saveAlert("suspicious_payload", "critical", ip, `Malicious payload: ${endpoint.substring(0, 60)}`, {}, userAgent);
    return { block: true, type: "suspicious_payload", severity: "critical" };
  }

  return { block: false };
}

async function saveAlert(type, severity, ip, description, metadata, userAgent) {
  try {
    const recent = await Alert.findOne({ ip, type, timestamp: { $gte: new Date(Date.now() - 60000) } });
    if (recent) return;
    const alert = await Alert.create({ type, severity, ip, description, metadata });
    if (severity === "critical") {
      const exists = await Rule.findOne({ type: "ip_block", value: ip, isActive: true });
      if (!exists) {
        await Rule.create({ type: "ip_block", value: ip, action: "block", reason: "[AUTO] " + description, isActive: true, priority: 200 });
        alert.autoBlocked = true;
        await alert.save();
      }
    }
  } catch (e) {
    console.error("Alert error:", e.message);
  }
}

// ── Firewall Middleware ──────────────────
let blockedIPs = new Set();
let blockedDomains = new Set();
let cacheTime = 0;

async function loadRules() {
  if (Date.now() - cacheTime < 30000) return;
  try {
    const rules = await Rule.find({ isActive: true }).lean();
    blockedIPs = new Set();
    blockedDomains = new Set();
    rules.forEach(r => {
      if (r.type === "ip_block") blockedIPs.add(r.value);
      if (r.type === "domain_block") blockedDomains.add(r.value.toLowerCase());
    });
    cacheTime = Date.now();
  } catch (e) {}
}

function getIP(req) {
  return (req.headers["x-forwarded-for"]?.split(",")[0] || req.connection?.remoteAddress || "0.0.0.0").replace("::ffff:", "");
}

async function firewall(req, res, next) {
  const start = Date.now();
  const ip = getIP(req);
  const endpoint = req.path;
  const userAgent = req.headers["user-agent"] || "";
  req.clientIP = ip;

  await loadRules();

  if (blockedIPs.has(ip)) {
    Log.create({ ip, method: req.method, endpoint, status: "blocked", statusCode: 403, responseTime: Date.now() - start, blockedReason: "IP blocked" }).catch(() => {});
    await Rule.findOneAndUpdate({ type: "ip_block", value: ip }, { $inc: { hitCount: 1 }, lastTriggered: new Date() }).catch(() => {});
    return res.status(403).json({ success: false, message: "BLOCKED: IP address is blocked by firewall", ip });
  }

  const host = (req.headers.host || "").split(":")[0].toLowerCase();
  for (const d of blockedDomains) {
    if (host === d || host.endsWith("." + d)) {
      Log.create({ ip, method: req.method, endpoint, status: "blocked", statusCode: 403, responseTime: Date.now() - start, blockedReason: "Domain blocked" }).catch(() => {});
      return res.status(403).json({ success: false, message: "BLOCKED: Domain is blocked by firewall" });
    }
  }

  const anomaly = await detectAnomaly(ip, endpoint, userAgent);
  if (anomaly.block) {
    Log.create({ ip, method: req.method, endpoint, status: "anomaly", statusCode: 403, responseTime: Date.now() - start, isAnomaly: true, blockedReason: anomaly.type }).catch(() => {});
    return res.status(403).json({ success: false, message: "BLOCKED: Anomaly detected - " + anomaly.type });
  }

  const origSend = res.send.bind(res);
  res.send = function(body) {
    Log.create({ ip, method: req.method, endpoint, status: anomaly.type ? "anomaly" : "allowed", statusCode: res.statusCode, responseTime: Date.now() - start, isAnomaly: !!anomaly.type }).catch(() => {});
    return origSend(body);
  };

  next();
}

app.use(firewall);

// ── Routes ───────────────────────────────

// Health
app.get("/health", (req, res) => {
  res.json({ success: true, status: "operational", service: "AI Firewall System", timestamp: new Date().toISOString(), uptime: Math.floor(process.uptime()) });
});

// Register
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success: false, message: "All fields required" });
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ success: false, message: "Email already exists" });
    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ username, email, password: hash, role: role === "admin" ? "admin" : "user" });
    const token = genToken({ id: user._id, role: user.role, username: user.username });
    res.status(201).json({ success: true, message: "Registered!", data: { token, user: { id: user._id, username: user.username, email: user.email, role: user.role } } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });
    const user = await User.findOne({ email }).select("+password");
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });
    if (user.lockedUntil && user.lockedUntil > Date.now()) return res.status(423).json({ success: false, message: "Account locked. Try later." });
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 5) user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
      await user.save();
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }
    user.loginAttempts = 0;
    user.lockedUntil = null;
    user.lastLogin = new Date();
    await user.save();
    const token = genToken({ id: user._id, role: user.role, username: user.username });
    res.json({ success: true, message: "Login successful", data: { token, user: { id: user._id, username: user.username, email: user.email, role: user.role } } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Get profile
app.get("/auth/me", protect, async (req, res) => {
  res.json({ success: true, data: { id: req.user._id, username: req.user.username, email: req.user.email, role: req.user.role } });
});

// Protected data
app.get("/api/data", protect, (req, res) => {
  res.json({ success: true, message: "Secure data", data: { user: req.user.username, ip: req.clientIP, time: new Date() } });
});

app.get("/api/public", (req, res) => {
  res.json({ success: true, message: "Public endpoint - firewall active", ip: req.clientIP });
});

// Block IP
app.post("/admin/block/ip", protect, adminOnly, async (req, res) => {
  try {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP required" });
    const exists = await Rule.findOne({ type: "ip_block", value: ip, isActive: true });
    if (exists) return res.status(409).json({ success: false, message: "IP already blocked" });
    const rule = await Rule.create({ type: "ip_block", value: ip, action: "block", reason: reason || "Manual block", createdBy: req.user._id, priority: 150 });
    cacheTime = 0;
    res.status(201).json({ success: true, message: `IP ${ip} blocked`, data: { rule } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Block Domain
app.post("/admin/block/domain", protect, adminOnly, async (req, res) => {
  try {
    const { domain, reason } = req.body;
    if (!domain) return res.status(400).json({ success: false, message: "Domain required" });
    const exists = await Rule.findOne({ type: "domain_block", value: domain.toLowerCase(), isActive: true });
    if (exists) return res.status(409).json({ success: false, message: "Domain already blocked" });
    const rule = await Rule.create({ type: "domain_block", value: domain.toLowerCase(), action: "block", reason: reason || "Manual block", createdBy: req.user._id, priority: 150 });
    cacheTime = 0;
    res.status(201).json({ success: true, message: `Domain ${domain} blocked`, data: { rule } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Get Rules
app.get("/admin/rules", protect, adminOnly, async (req, res) => {
  try {
    const rules = await Rule.find({ isActive: true }).sort({ priority: -1, createdAt: -1 });
    res.json({ success: true, data: { rules, total: rules.length } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Delete Rule
app.delete("/admin/rules/:id", protect, adminOnly, async (req, res) => {
  try {
    await Rule.findByIdAndUpdate(req.params.id, { isActive: false });
    cacheTime = 0;
    res.json({ success: true, message: "Rule removed" });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Get Logs
app.get("/admin/logs", protect, adminOnly, async (req, res) => {
  try {
    const { status, ip, isAnomaly } = req.query;
    const filter = {};
    if (status) filter.status = status;
    if (ip) filter.ip = { $regex: ip };
    if (isAnomaly === "true") filter.isAnomaly = true;
    const logs = await Log.find(filter).sort({ timestamp: -1 }).limit(200);
    const total = await Log.countDocuments(filter);
    res.json({ success: true, data: { logs, total } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Get Alerts
app.get("/admin/alerts", protect, adminOnly, async (req, res) => {
  try {
    const { severity, isResolved } = req.query;
    const filter = {};
    if (severity) filter.severity = severity;
    if (isResolved !== "all") filter.isResolved = isResolved === "true";
    const alerts = await Alert.find(filter).sort({ timestamp: -1 }).limit(100);
    const total = await Alert.countDocuments(filter);
    const criticalCount = await Alert.countDocuments({ severity: "critical", isResolved: false });
    res.json({ success: true, data: { alerts, total, criticalCount } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Resolve Alert
app.patch("/admin/alerts/:id/resolve", protect, adminOnly, async (req, res) => {
  try {
    const alert = await Alert.findByIdAndUpdate(req.params.id, { isResolved: true, resolvedAt: new Date() }, { new: true });
    res.json({ success: true, message: "Alert resolved", data: { alert } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Stats
app.get("/admin/stats", protect, adminOnly, async (req, res) => {
  try {
    const last24h = new Date(Date.now() - 86400000);
    const last1h = new Date(Date.now() - 3600000);
    const [total, blocked, anomaly, rules, alerts, critical, recent, topIPs, chart] = await Promise.all([
      Log.countDocuments({ timestamp: { $gte: last24h } }),
      Log.countDocuments({ timestamp: { $gte: last24h }, status: "blocked" }),
      Log.countDocuments({ timestamp: { $gte: last24h }, isAnomaly: true }),
      Rule.countDocuments({ isActive: true }),
      Alert.countDocuments({ isResolved: false }),
      Alert.countDocuments({ severity: "critical", isResolved: false }),
      Log.countDocuments({ timestamp: { $gte: last1h } }),
      Log.aggregate([
        { $match: { status: "blocked", timestamp: { $gte: last24h } } },
        { $group: { _id: "$ip", count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 5 },
        { $project: { ip: "$_id", count: 1, _id: 0 } }
      ]),
      Log.aggregate([
        { $match: { timestamp: { $gte: new Date(Date.now() - 43200000) } } },
        { $group: { _id: { $dateToString: { format: "%H:00", date: "$timestamp" } }, total: { $sum: 1 }, blocked: { $sum: { $cond: [{ $eq: ["$status", "blocked"] }, 1, 0] } }, allowed: { $sum: { $cond: [{ $eq: ["$status", "allowed"] }, 1, 0] } } } },
        { $sort: { _id: 1 } }
      ])
    ]);
    res.json({ success: true, data: { summary: { totalRequests: total, blockedRequests: blocked, allowedRequests: total - blocked - anomaly, anomalyRequests: anomaly, blockRate: total > 0 ? ((blocked / total) * 100).toFixed(1) : 0, activeRules: rules, unresolvedAlerts: alerts, criticalAlerts: critical, recentRequests: recent }, topBlockedIPs: topIPs, trafficByHour: chart } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Simulate Attack
app.post("/admin/simulate/attack", protect, adminOnly, async (req, res) => {
  try {
    const { type = "burst", targetIP = "10.0.0.99" } = req.body;
    const count = type === "ddos" ? 55 : 25;
    let detected = 0;
    for (let i = 0; i < count; i++) {
      const result = await detectAnomaly(targetIP, `/api/test-${i % 5}`, "AttackBot/1.0");
      if (result.type) detected++;
    }
    res.json({ success: true, message: "Simulation complete", data: { type, targetIP, requestsSent: count, anomaliesDetected: detected } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Serve frontend
app.use(express.static(path.join(__dirname, "../frontend")));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/auth") || req.path.startsWith("/api") || req.path.startsWith("/admin") || req.path === "/health") return next();
  res.sendFile(path.join(__dirname, "../frontend/index.html"), err => { if (err) next(); });
});

// Error handler
app.use((err, req, res, next) => {
  res.status(500).json({ success: false, message: err.message });
});

app.listen(PORT, () => {
  console.log("");
  console.log("============================================");
  console.log("  AI FIREWALL SYSTEM - ONLINE");
  console.log("  Port: " + PORT);
  console.log("============================================");
  console.log("");
});
