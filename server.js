const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "30kb" }));

const required = ["DATABASE_URL", "ADMIN_PASSWORD", "JWT_SECRET", "ALLOWED_ORIGIN"];
for (const name of required) {
  if (!process.env[name]) {
    console.error("Missing required environment variable:", name);
    process.exit(1);
  }
}
if (process.env.ADMIN_PASSWORD.length < 12) {
  console.error("ADMIN_PASSWORD must be at least 12 characters.");
  process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

const allowedOrigins = process.env.ALLOWED_ORIGIN.split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS offers (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(100) NOT NULL,
      price VARCHAR(40) NOT NULL,
      description VARCHAR(500) NOT NULL DEFAULT '',
      starts_at DATE NOT NULL,
      ends_at DATE NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (ends_at >= starts_at)
    )
  `);
}

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const writeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false });

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  try {
    req.owner = jwt.verify(token, process.env.JWT_SECRET);
    if (req.owner.role !== "owner") throw new Error("bad role");
    next();
  } catch (_) {
    return res.status(401).json({ error: "Please sign in again." });
  }
}

function validDate(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + "T00:00:00Z"));
}
function cleanText(v, max) { return typeof v === "string" ? v.trim().slice(0, max) : ""; }
function mapOffer(row) {
  return {
    id: row.id,
    title: row.title,
    price: row.price,
    description: row.description,
    start: String(row.starts_at).slice(0, 10),
    end: String(row.ends_at).slice(0, 10),
    active: row.active
  };
}

app.get("/", (req, res) => res.json({ service: "The Farmer's Hideout Offers API", status: "ok" }));
app.get("/health", async (req, res) => {
  try { await pool.query("SELECT 1"); res.json({ status: "ok", database: "connected" }); }
  catch (_) { res.status(503).json({ status: "error", database: "unavailable" }); }
});

app.post("/api/admin/login", loginLimiter, async (req, res) => {
  const password = cleanText(req.body && req.body.password, 200);
  if (!password || !(await bcrypt.compare(password, await bcrypt.hash(process.env.ADMIN_PASSWORD, 10)))) {
    return res.status(401).json({ error: "Incorrect password." });
  }
  const token = jwt.sign({ role: "owner" }, process.env.JWT_SECRET, { expiresIn: "8h" });
  res.json({ token, expiresIn: 28800 });
});

app.get("/api/offers", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, title, price, description, starts_at, ends_at, active
      FROM offers
      WHERE active = TRUE AND starts_at <= CURRENT_DATE AND ends_at >= CURRENT_DATE
      ORDER BY created_at DESC
    `);
    res.set("Cache-Control", "no-store");
    res.json({ offers: result.rows.map(mapOffer) });
  } catch (err) {
    console.error("Public offers error:", err.message);
    res.status(500).json({ error: "Could not load offers." });
  }
});

app.get("/api/admin/offers", auth, async (req, res) => {
  try {
    const result = await pool.query("SELECT id,title,price,description,starts_at,ends_at,active FROM offers ORDER BY created_at DESC");
    res.json({ offers: result.rows.map(mapOffer) });
  } catch (_) { res.status(500).json({ error: "Could not load offers." }); }
});

app.post("/api/admin/offers", auth, writeLimiter, async (req, res) => {
  const title = cleanText(req.body && req.body.title, 100);
  const price = cleanText(req.body && req.body.price, 40);
  const description = cleanText(req.body && req.body.description, 500);
  const start = req.body && req.body.start;
  const end = req.body && req.body.end;
  if (!title || !price || !validDate(start) || !validDate(end) || end < start) {
    return res.status(400).json({ error: "Enter a title, price, valid start date and end date (end must not be before start)." });
  }
  try {
    const result = await pool.query(
      "INSERT INTO offers(title,price,description,starts_at,ends_at) VALUES($1,$2,$3,$4,$5) RETURNING id,title,price,description,starts_at,ends_at,active",
      [title, price, description, start, end]
    );
    res.status(201).json({ offer: mapOffer(result.rows[0]) });
  } catch (_) { res.status(500).json({ error: "Could not create offer." }); }
});

app.patch("/api/admin/offers/:id", auth, writeLimiter, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Invalid offer ID." });
  const active = req.body && req.body.active;
  if (typeof active !== "boolean") return res.status(400).json({ error: "Send active: true or false." });
  try {
    const result = await pool.query("UPDATE offers SET active=$1, updated_at=NOW() WHERE id=$2 RETURNING id,title,price,description,starts_at,ends_at,active", [active, id]);
    if (!result.rowCount) return res.status(404).json({ error: "Offer not found." });
    res.json({ offer: mapOffer(result.rows[0]) });
  } catch (_) { res.status(500).json({ error: "Could not update offer." }); }
});

app.delete("/api/admin/offers/:id", auth, writeLimiter, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Invalid offer ID." });
  try {
    const result = await pool.query("DELETE FROM offers WHERE id=$1 RETURNING id", [id]);
    if (!result.rowCount) return res.status(404).json({ error: "Offer not found." });
    res.json({ ok: true });
  } catch (_) { res.status(500).json({ error: "Could not delete offer." }); }
});

const port = process.env.PORT || 10000;
initDb().then(() => {
  app.listen(port, "0.0.0.0", () => console.log("Offers API listening on port " + port));
}).catch(err => {
  console.error("Database initialization failed:", err.message);
  process.exit(1);
});
