// server.js  (replace your existing backend with this file)

const mysql = require("mysql2");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(cors());

// Ensure uploads folder exists
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Serve uploaded images
app.use("/uploads", express.static(UPLOADS_DIR));

// ============ MULTER STORAGE ============
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

// ============ DB CONNECTION ============
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "naveen@123",
  database: "DWJD",
  // optional: set timezone to local if you want mysql2 client to convert dates
  // timezone: 'local'
});
db.connect((err) => {
  if (err) {
    console.error("DB connection failed:", err);
    process.exit(1);
  }
  console.log("Database connected");
});

// ============ UTIL ============
function generatePIN() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let pin = "";
  for (let i = 0; i < 6; i++) {
    pin += chars[Math.floor(Math.random() * chars.length)];
  }
  return pin;
}

// format Date -> MySQL DATETIME 'YYYY-MM-DD HH:MM:SS'
function toMysqlDatetime(d) {
  const dt = new Date(d);
  const yyyy = dt.getFullYear();
  const mm = String(dt.getMonth() + 1).padStart(2, "0");
  const dd = String(dt.getDate()).padStart(2, "0");
  const hh = String(dt.getHours()).padStart(2, "0");
  const mi = String(dt.getMinutes()).padStart(2, "0");
  const ss = String(dt.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

/* =====================================================
   SIGNUP (with photo upload)
   multipart/form-data field: profile_photo
===================================================== */
app.post("/signup", upload.single("profile_photo"), (req, res) => {
  const {
    firstname, lastname, address, email,
    ph_no, user_name, password, user_type,
  } = req.body;

  const profile_photo = req.file ? `/uploads/${req.file.filename}` : null;

  const checkQ = "SELECT id FROM details WHERE user_name = ?";
  db.query(checkQ, [user_name], (err, rows) => {
    if (err) {
      console.error("signup checkQ error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    if (rows.length > 0) return res.send({ status: "exists" });

    const insertQ = `
      INSERT INTO details
      (firstname, lastname, address, email, ph_no, profile_photo, user_name, password, user_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(
      insertQ,
      [firstname, lastname, address, email, ph_no, profile_photo, user_name, password, user_type],
      (err2) => {
        if (err2) {
          console.error("signup insert error:", err2);
          return res.status(500).send({ status: "error", message: "Insert failed" });
        }
        return res.send({ status: "success" });
      }
    );
  });
});

/* =====================================================
   LOGIN
===================================================== */
app.post("/login", (req, res) => {
  const { user_name, password, user_type } = req.body;
  const q = `SELECT * FROM details WHERE user_name=? AND password=? AND user_type=?`;
  db.query(q, [user_name, password, user_type], (err, result) => {
    if (err) {
      console.error("login error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    if (result.length === 0) return res.send({ status: "fail" });
    return res.send({ status: "success", user: result[0] });
  });
});

/* =====================================================
   ADD FOOD TRIP
   POST /addTrip
===================================================== */
app.post("/addTrip", (req, res) => {
  const { user_id, food_type, quantity, price, provider_type, location } = req.body;
  const pin = generatePIN();
  // store expiry as formatted datetime (avoids timezone confusion)
  const expiry = toMysqlDatetime(Date.now() + 60 * 60 * 1000);

  const q = `
    INSERT INTO trips
    (user_id, food_type, quantity, price, provider_type, location, status, otp, otp_expiry)
    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
  `;
  db.query(q, [user_id, food_type, quantity, price, provider_type, location, pin, expiry], (err, result) => {
    if (err) {
      console.error("addTrip error:", err);
      return res.status(500).send({ status: "error", message: "Trip insert failed" });
    }
    return res.send({ status: "success", trip_id: result.insertId, pin });
  });
});

/* =====================================================
   ADD CLOTHES DONATION
   POST /addClothes
   NOTE: DB column is cloth_condition
===================================================== */
app.post("/addClothes", (req, res) => {
  const { user_id, cloth_type, quantity, condition, location } = req.body;
  const pin = generatePIN();
  const expiry = toMysqlDatetime(Date.now() + 60 * 60 * 1000);

  const q = `
    INSERT INTO clothes
    (user_id, cloth_type, quantity, cloth_condition, location, status, otp, otp_expiry)
    VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
  `;
  db.query(q, [user_id, cloth_type, quantity, condition, location, pin, expiry], (err, result) => {
    if (err) {
      console.error("addClothes error:", err);
      return res.status(500).send({ status: "error", message: "Clothes insert failed" });
    }
    return res.send({ status: "success", trip_id: result.insertId, pin });
  });
});

/* =====================================================
   GET PENDING FOOD TRIPS
   GET /get-trips
===================================================== */
app.get("/get-trips", (req, res) => {
  const q = "SELECT * FROM trips WHERE status='pending' ORDER BY created_at DESC";
  db.query(q, (err, result) => {
    if (err) {
      console.error("get-trips error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    return res.send(result);
  });
});

/* =====================================================
   GET PENDING CLOTHES TRIPS
   GET /get-clothes-trips
===================================================== */
app.get("/get-clothes-trips", (req, res) => {
  const q = "SELECT * FROM clothes WHERE status='pending' ORDER BY created_at DESC";
  db.query(q, (err, result) => {
    if (err) {
      console.error("get-clothes-trips error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    return res.send(result);
  });
});

/* =====================================================
   GET ALL PENDING TRIPS (COMBINED)
===================================================== */
app.get("/get-all-trips", (req, res) => {
  const q = `
    SELECT id, 'food' AS type, food_type AS item, quantity, price, location, status, created_at
    FROM trips WHERE status='pending'
    UNION ALL
    SELECT id, 'clothes' AS type, cloth_type AS item, quantity, NULL AS price, location, status, created_at
    FROM clothes WHERE status='pending'
    ORDER BY created_at DESC
  `;
  db.query(q, (err, result) => {
    if (err) {
      console.error("get-all-trips error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    return res.send(result);
  });
});

/* =====================================================
   PICK FOOD TRIP
   POST /pick-trip
===================================================== */
app.post("/pick-trip", (req, res) => {
  const { trip_id, rider_id } = req.body;
  const q = `UPDATE trips SET status='picked', rider_id=? WHERE id=? AND status='pending'`;
  db.query(q, [rider_id, trip_id], (err, result) => {
    if (err) {
      console.error("pick-trip update error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    if (result.affectedRows === 0) return res.send({ status: "fail", message: "Already taken" });

    db.query("SELECT otp FROM trips WHERE id=?", [trip_id], (err2, rows) => {
      if (err2) {
        console.error("pick-trip select otp error:", err2);
        return res.status(500).send({ status: "error", message: "DB error" });
      }
      if (!rows || rows.length === 0) {
        return res.status(500).send({ status: "error", message: "Trip not found after update" });
      }
      return res.send({ status: "success", pin: rows[0].otp });
    });
  });
});

/* =====================================================
   PICK CLOTHES TRIP
   POST /pick-clothes-trip
===================================================== */
app.post("/pick-clothes-trip", (req, res) => {
  const { trip_id, rider_id } = req.body;
  const q = `UPDATE clothes SET status='picked', rider_id=? WHERE id=? AND status='pending'`;
  db.query(q, [rider_id, trip_id], (err, result) => {
    if (err) {
      console.error("pick-clothes-trip update error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    if (result.affectedRows === 0) return res.send({ status: "fail", message: "Already taken" });

    db.query("SELECT otp FROM clothes WHERE id=?", [trip_id], (err2, rows) => {
      if (err2) {
        console.error("pick-clothes-trip select otp error:", err2);
        return res.status(500).send({ status: "error", message: "DB error" });
      }
      if (!rows || rows.length === 0) {
        return res.status(500).send({ status: "error", message: "Clothes trip not found after update" });
      }
      return res.send({ status: "success", pin: rows[0].otp });
    });
  });
});

/* =====================================================
   REJECT TRIP (FOOD)
   POST /reject-trip
===================================================== */
app.post("/reject-trip", (req, res) => {
  const { trip_id, rider_id, reason } = req.body;
  const q = `UPDATE trips SET status='rejected', rejection_reason=? WHERE id=?`;
  db.query(q, [reason, trip_id], (err, result) => {
    if (err) {
      console.error("reject-trip error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    if (result.affectedRows === 0) return res.send({ status: "fail", message: "No such trip" });
    return res.send({ status: "success" });
  });
});

/* =====================================================
   VERIFY PIN (GENERIC) - checks trips then clothes
   POST /verify-pin
===================================================== */
app.post("/verify-pin", (req, res) => {
  const { trip_id, rider_id, pin } = req.body;

  // check trips
  db.query("SELECT otp, otp_expiry, rider_id, status FROM trips WHERE id=?", [trip_id], (err, rows) => {
    if (err) {
      console.error("verify-pin trips select error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }

    if (rows.length > 0) {
      const data = rows[0];

      // defensive checks
      if (!data.rider_id || Number(data.rider_id) !== Number(rider_id)) return res.send({ status: "not_allowed" });
      if (data.status !== "picked") return res.send({ status: "not_allowed" });

      // Use getTime() to compare to avoid timezone string parse edge cases
      const expiryTime = new Date(data.otp_expiry).getTime();
      if (Date.now() > expiryTime) return res.send({ status: "expired" });

      if (String(pin) !== String(data.otp)) return res.send({ status: "invalid" });

      db.query("UPDATE trips SET status='completed' WHERE id=?", [trip_id], (err2) => {
        if (err2) {
          console.error("verify-pin trips update error:", err2);
          return res.status(500).send({ status: "error", message: "DB error" });
        }
        return res.send({ status: "success", type: "trips" });
      });
      return;
    }

    // check clothes
    db.query("SELECT otp, otp_expiry, rider_id, status FROM clothes WHERE id=?", [trip_id], (err3, rows3) => {
      if (err3) {
        console.error("verify-pin clothes select error:", err3);
        return res.status(500).send({ status: "error", message: "DB error" });
      }
      if (rows3.length === 0) return res.send({ status: "not_found" });

      const data = rows3[0];
      if (!data.rider_id || Number(data.rider_id) !== Number(rider_id)) return res.send({ status: "not_allowed" });
      if (data.status !== "picked") return res.send({ status: "not_allowed" });

      const expiryTime = new Date(data.otp_expiry).getTime();
      if (Date.now() > expiryTime) return res.send({ status: "expired" });

      if (String(pin) !== String(data.otp)) return res.send({ status: "invalid" });

      db.query("UPDATE clothes SET status='completed' WHERE id=?", [trip_id], (err4) => {
        if (err4) {
          console.error("verify-pin clothes update error:", err4);
          return res.status(500).send({ status: "error", message: "DB error" });
        }
        return res.send({ status: "success", type: "clothes" });
      });
    });
  });
});

/* =====================================================
   MY DONATIONS (FOOD)
===================================================== */
app.get("/my-donations/:user_id", (req, res) => {
  db.query("SELECT * FROM trips WHERE user_id=? ORDER BY created_at DESC", [req.params.user_id], (err, result) => {
    if (err) {
      console.error("my-donations error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    return res.send(result);
  });
});

/* =====================================================
   MY DONATIONS (CLOTHES)
===================================================== */
app.get("/my-clothes-donations/:user_id", (req, res) => {
  db.query("SELECT * FROM clothes WHERE user_id=? ORDER BY created_at DESC", [req.params.user_id], (err, result) => {
    if (err) {
      console.error("my-clothes-donations error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    return res.send(result);
  });
});

/* =====================================================
   MY TRIPS (FOOD) - RIDER
===================================================== */
app.get("/my-trips/:rider_id", (req, res) => {
  db.query("SELECT * FROM trips WHERE rider_id=? ORDER BY created_at DESC", [req.params.rider_id], (err, result) => {
    if (err) {
      console.error("my-trips error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    return res.send(result);
  });
});

/* =====================================================
   MY TRIPS (CLOTHES) - RIDER
===================================================== */
app.get("/my-clothes-trips/:rider_id", (req, res) => {
  db.query("SELECT * FROM clothes WHERE rider_id=? ORDER BY created_at DESC", [req.params.rider_id], (err, result) => {
    if (err) {
      console.error("my-clothes-trips error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    return res.send(result);
  });
});

/* =====================================================
   CHECK TRIP STATUS (GENERIC)
===================================================== */
app.get("/check-trip-status/:trip_id", (req, res) => {
  const { trip_id } = req.params;

  db.query("SELECT status FROM trips WHERE id=?", [trip_id], (err, rows) => {
    if (err) {
      console.error("check-trip-status trips select error:", err);
      return res.status(500).send({ status: "error", message: "DB error" });
    }
    if (rows.length > 0) return res.send({ status: "success", trip_status: rows[0].status });

    db.query("SELECT status FROM clothes WHERE id=?", [trip_id], (err2, rows2) => {
      if (err2) {
        console.error("check-trip-status clothes select error:", err2);
        return res.status(500).send({ status: "error", message: "DB error" });
      }
      if (rows2.length > 0) return res.send({ status: "success", trip_status: rows2[0].status });
      return res.send({ status: "not_found" });
    });
  });
});

/* =====================================================
   SERVER START
===================================================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
