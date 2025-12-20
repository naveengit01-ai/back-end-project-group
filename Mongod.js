require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const twilio = require("twilio");

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
app.get("/", (_, res) => res.send("Backend running 🚀"));

/* ================= FILE UPLOAD (RENDER SAFE) ================= */
const UPLOADS_DIR = "/tmp/uploads";
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOADS_DIR),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
  }),
  limits: { fileSize: 2 * 1024 * 1024 }
});

/* ================= DATABASE ================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

/* ================= MODELS ================= */
const User = mongoose.model("User", new mongoose.Schema({
  firstname: String,
  lastname: String,
  address: String,
  email: String,
  ph_no: String,
  user_name: { type: String, unique: true },
  password: String,
  user_type: String,
  profile_photo: String
}, { timestamps: true }));

const TripSchema = {
  user_id: mongoose.Schema.Types.ObjectId,
  rider_id: mongoose.Schema.Types.ObjectId,
  status: { type: String, default: "pending" },
  otp: String,
  otp_expiry: Date
};

const Trip = mongoose.model("Trip", new mongoose.Schema({
  ...TripSchema,
  food_type: String,
  quantity: Number,
  price: Number,
  provider_type: String,
  location: String
}, { timestamps: true }));

const Clothes = mongoose.model("Clothes", new mongoose.Schema({
  ...TripSchema,
  cloth_type: String,
  quantity: Number,
  cloth_condition: String,
  location: String
}, { timestamps: true }));

/* ================= JWT ================= */
function generateToken(user) {
  return jwt.sign(
    { id: user._id, role: user.user_type },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES }
  );
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ status: "unauthorized" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ status: "invalid_token" });
  }
}

/* ================= OTP ================= */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/* ================= EMAIL ================= */
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendOtpMail(email, otp) {
  await mailer.sendMail({
    from: `"DWJD App" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Your Pickup OTP",
    html: `<h2>Your OTP: ${otp}</h2><p>Valid for 1 hour.</p>`
  });
}

/* ================= SMS (TWILIO) ================= */
const smsClient = twilio(
  process.env.TWILIO_SID,
  process.env.TWILIO_AUTH
);

async function sendOtpSMS(phone, otp) {
  await smsClient.messages.create({
    body: `DWJD Pickup OTP: ${otp}`,
    from: process.env.TWILIO_PHONE,
    to: phone
  });
}

/* ================= AUTH ROUTES ================= */
app.post("/signup", upload.single("profile_photo"), async (req, res) => {
  const exists = await User.findOne({ user_name: req.body.user_name });
  if (exists) return res.json({ status: "exists" });

  await User.create({
    ...req.body,
    profile_photo: req.file?.filename || null
  });

  res.json({ status: "success" });
});

app.post("/login", async (req, res) => {
  const user = await User.findOne(req.body);
  if (!user) return res.json({ status: "fail" });

  const token = generateToken(user);
  res.json({ status: "success", token, user });
});

/* ================= CREATE DONATION ================= */
async function createTrip(Model, body) {
  const otp = generateOTP();
  const trip = await Model.create({
    ...body,
    otp,
    otp_expiry: new Date(Date.now() + 60 * 60 * 1000)
  });

  const user = await User.findById(body.user_id);
  if (user?.email) await sendOtpMail(user.email, otp);
  if (user?.ph_no) await sendOtpSMS(user.ph_no, otp);

  return trip;
}

app.post("/addTrip", auth, async (req, res) => {
  const trip = await createTrip(Trip, req.body);
  res.json({ status: "success", trip_id: trip._id });
});

app.post("/addClothes", auth, async (req, res) => {
  const trip = await createTrip(Clothes, req.body);
  res.json({ status: "success", trip_id: trip._id });
});

/* ================= RESEND OTP ================= */
app.post("/resend-otp", auth, async (req, res) => {
  let trip = await Trip.findById(req.body.trip_id) ||
             await Clothes.findById(req.body.trip_id);

  if (!trip) return res.json({ status: "not_found" });

  const otp = generateOTP();
  trip.otp = otp;
  trip.otp_expiry = new Date(Date.now() + 60 * 60 * 1000);
  await trip.save();

  const user = await User.findById(trip.user_id);
  if (user?.email) await sendOtpMail(user.email, otp);
  if (user?.ph_no) await sendOtpSMS(user.ph_no, otp);

  res.json({ status: "success" });
});

/* ================= VERIFY OTP ================= */
app.post("/verify-pin", auth, async (req, res) => {
  let trip = await Trip.findById(req.body.trip_id) ||
             await Clothes.findById(req.body.trip_id);

  if (!trip) return res.json({ status: "not_found" });

  if (Date.now() > new Date(trip.otp_expiry))
    return res.json({ status: "expired" });

  if (trip.otp !== req.body.pin)
    return res.json({ status: "invalid" });

  trip.status = "completed";
  trip.otp = null;
  trip.otp_expiry = null;
  await trip.save();

  res.json({ status: "success" });
});

/* ================= START ================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🔥 Server running on ${PORT}`));
