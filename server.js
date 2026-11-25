const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "20kb" }));
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false
});

const PORT = process.env.PORT || 3000;
const ADMIN = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.JWT_SECRET;

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const data = jwt.verify(token, SECRET);
    if (data.role !== "admin") throw new Error("role");
    next();
  } catch {
    res.status(401).json({ message: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn" });
  }
}

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};

  if (!ADMIN || !ADMIN_PASSWORD || !SECRET) {
    return res.status(500).json({ message: "Máy chủ chưa cấu hình Admin" });
  }

  if (username !== ADMIN || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: "Sai tài khoản hoặc mật khẩu" });
  }

  const token = jwt.sign({ role: "admin" }, SECRET, { expiresIn: "12h" });
  res.json({ token });
});

app.post("/api/admin/keys", auth, async (req, res) => {
  try {
    const days = Number(req.body.days);

    if (![0, 1, 7, 30, 365].includes(days)) {
      return res.status(400).json({ message: "Thời hạn không hợp lệ" });
    }

    const key = "TBR-V100-" + crypto.randomBytes(9).toString("hex").toUpperCase();
    const id = crypto.randomUUID();
    const expires = days === 0 ? null : new Date(Date.now() + days * 86400000);

    await pool.query(
      "INSERT INTO app_keys(id,key_value,expires_at) VALUES($1,$2,$3)",
      [id, key, expires]
    );

    res.json({ id, key, expires_at: expires });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Không tạo được KEY" });
  }
});

app.get("/api/admin/keys", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,key_value AS key,active,expires_at,created_at FROM app_keys ORDER BY created_at DESC"
    );
    res.json({ keys: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Không tải được KEY" });
  }
});

app.patch("/api/admin/keys/:id", auth, async (req, res) => {
  try {
    if (typeof req.body.active !== "boolean") {
      return res.status(400).json({ message: "Dữ liệu không hợp lệ" });
    }

    const result = await pool.query(
      "UPDATE app_keys SET active=$1 WHERE id=$2 RETURNING id",
      [req.body.active, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Không tìm thấy KEY" });
    }

    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Không cập nhật được KEY" });
  }
});

app.post("/api/verify-key", async (req, res) => {
  try {
    const key = String((req.body || {}).key || "").trim();

    if (!key) {
      return res.json({ valid: false, message: "Vui lòng nhập KEY" });
    }

    const result = await pool.query(
      "SELECT active,expires_at FROM app_keys WHERE key_value=$1",
      [key]
    );

    const item = result.rows[0];
    const valid = !!item && item.active &&
      (!item.expires_at || new Date(item.expires_at) > new Date());

    res.json(
      valid
        ? { valid: true }
        : { valid: false, message: "KEY sai, đã khóa hoặc hết hạn!" }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ valid: false, message: "Lỗi máy chủ" });
  }
});

async function start() {
  if (!process.env.DATABASE_URL || !SECRET || !ADMIN || !ADMIN_PASSWORD) {
    throw new Error("Thiếu cấu hình Environment");
  }

  await pool.query(`CREATE TABLE IF NOT EXISTS app_keys (
    id UUID PRIMARY KEY,
    key_value TEXT UNIQUE NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  app.listen(PORT, () => {
    console.log("TIẾN BỜ RAI V100 SERVER đang chạy cổng " + PORT);
  });
}

start().catch(err => {
  console.error(err);
  process.exit(1);
});