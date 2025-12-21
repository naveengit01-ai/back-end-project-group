require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:3000",
      "https://back-end-project-group.onrender.com"
    ],
    credentials: true
  })
);

/* ================= HEALTH ================= */
app.get("/", (_, res) => res.send("DWJD Backend Running 🚀"));

/* ================= DATABASE ================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

/* ================= FILE UPLOAD ================= */
const UPLOADS_DIR = "/tmp/uploads";
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOADS_DIR),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
  })
});

/* ================= MODEL ================= */
const User = mongoose.model(
  "User",
  new mongoose.Schema(
    {
      firstname: String,
      lastname: String,
      email: String,
      ph_no: String,
      user_name: { type: String, unique: true },
      password: String,
      user_type: String,
      profile_photo: String,
      signup_otp: String,
      otp_expiry: Date,
      last_otp_sent: Date,
      is_verified: { type: Boolean, default: false }
    },
    { timestamps: true }
  )
);

/* ================= EMAIL (FIXED) ================= */
const mailer = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* ================= HELPERS ================= */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function strongPassword(pwd) {
  return /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(pwd);
}

async function sendOTP(email, otp) {
  console.log("📧 Sending OTP to:", email);

  const info = await mailer.sendMail({
    from: {
      name: "DWJD Support",
      address: process.env.EMAIL_USER
    },
    to: email,
    subject: "DWJD Account Verification Code",
    html: `
      <div style="font-family: Arial; padding:20px">
        <h2>Verify your DWJD account</h2>
        <p>Your One-Time Password (OTP):</p>
        <h1 style="letter-spacing:4px">${otp}</h1>
        <p>This OTP is valid for <b>10 minutes</b>.</p>
        <p>If you didn’t request this, please ignore.</p>
        <br/>
        <p>— DWJD Team</p>
      </div>
    `
  });

  console.log("✅ Mail sent:", info.messageId);
}

/* ================= SIGNUP ================= */
app.post("/signup", upload.single("profile_photo"), async (req, res) => {
  try {
    const {
      firstname,
      lastname,
      email,
      ph_no,
      user_name,
      password,
      user_type
    } = req.body;

    if (!email || !email.includes("@")) {
      return res.json({ status: "invalid_email" });
    }

    const exists = await User.findOne({ user_name });
    if (exists) return res.json({ status: "exists" });

    if (!strongPassword(password)) {
      return res.json({ status: "weak_password" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    const user = await User.create({
      firstname,
      lastname,
      email,
      ph_no,
      user_name,
      password: hashedPassword,
      user_type,
      profile_photo: req.file?.filename || null,
      signup_otp: otp,
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
      last_otp_sent: new Date()
    });

    await sendOTP(user.email, otp);

    res.json({ status: "success" });
  } catch (err) {
    console.error("❌ Signup error:", err);
    res.status(500).json({ status: "mail_failed" });
  }
});

/* ================= RESEND OTP ================= */
app.post("/resend-signup-otp", async (req, res) => {
  const { user_name } = req.body;

  const user = await User.findOne({ user_name });
  if (!user) return res.json({ status: "not_found" });

  if (Date.now() - user.last_otp_sent < 30_000) {
    return res.json({ status: "wait", seconds: 30 });
  }

  const otp = generateOTP();
  user.signup_otp = otp;
  user.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
  user.last_otp_sent = new Date();
  await user.save();

  await sendOTP(user.email, otp);

  res.json({ status: "resent" });
});

/* ================= VERIFY OTP ================= */
app.post("/verify-signup-otp", async (req, res) => {
  const { user_name, otp } = req.body;

  const user = await User.findOne({ user_name });
  if (!user) return res.json({ status: "not_found" });

  if (Date.now() > user.otp_expiry) return res.json({ status: "expired" });
  if (user.signup_otp !== otp) return res.json({ status: "invalid" });

  user.is_verified = true;
  user.signup_otp = null;
  user.otp_expiry = null;
  await user.save();

  res.json({ status: "verified" });
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  const { user_name, password, user_type } = req.body;

  const user = await User.findOne({ user_name, user_type });
  if (!user) return res.json({ status: "fail" });
  if (!user.is_verified) return res.json({ status: "not_verified" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ status: "fail" });

  const token = jwt.sign(
    { id: user._id, role: user.user_type },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    status: "success",
    token,
    user: {
      _id: user._id,
      firstname: user.firstname,
      user_type: user.user_type
    }
  });
});

/* ================= KEEP RENDER ALIVE ================= */
app.get("/health", (_, res) => {
  res.status(200).json({ status: "ok" });
});

/* ================= START ================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);
