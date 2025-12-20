require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");

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

/* ================= HEALTH CHECK ================= */
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

/* ================= FILE UPLOAD (RENDER SAFE) ================= */
// Render allows writing ONLY to /tmp
const UPLOADS_DIR = "/tmp/uploads";
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024 // 2MB max (safe)
  }
});

/* ================= DATABASE ================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

/* ================= MODELS ================= */
const User = mongoose.model(
  "User",
  new mongoose.Schema(
    {
      firstname: String,
      lastname: String,
      address: String,
      email: String,
      ph_no: String,
      user_name: { type: String, unique: true },
      password: String,
      user_type: String, // user | rider
      profile_photo: String
    },
    { timestamps: true }
  )
);

const Trip = mongoose.model(
  "Trip",
  new mongoose.Schema(
    {
      user_id: mongoose.Schema.Types.ObjectId,
      rider_id: mongoose.Schema.Types.ObjectId,
      food_type: String,
      quantity: Number,
      price: Number,
      provider_type: String,
      location: String,
      status: { type: String, default: "pending" },
      otp: String,
      otp_expiry: Date
    },
    { timestamps: true }
  )
);

const Clothes = mongoose.model(
  "Clothes",
  new mongoose.Schema(
    {
      user_id: mongoose.Schema.Types.ObjectId,
      rider_id: mongoose.Schema.Types.ObjectId,
      cloth_type: String,
      quantity: Number,
      cloth_condition: String,
      location: String,
      status: { type: String, default: "pending" },
      otp: String,
      otp_expiry: Date
    },
    { timestamps: true }
  )
);

/* ================= UTILS ================= */
function generatePIN() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let pin = "";
  for (let i = 0; i < 6; i++) {
    pin += chars[Math.floor(Math.random() * chars.length)];
  }
  return pin;
}

/* ================= AUTH ================= */
app.post("/signup", upload.single("profile_photo"), async (req, res) => {
  try {
    const exists = await User.findOne({ user_name: req.body.user_name });
    if (exists) return res.json({ status: "exists" });

    await User.create({
      firstname: req.body.firstname,
      lastname: req.body.lastname,
      address: req.body.address,
      email: req.body.email,
      ph_no: req.body.ph_no,
      user_name: req.body.user_name,
      password: req.body.password, // (hash later)
      user_type: req.body.user_type,
      profile_photo: req.file ? req.file.filename : null
    });

    res.json({ status: "success" });
  } catch (err) {
    console.error("❌ Signup error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/login", async (req, res) => {
  const { user_name, password, user_type } = req.body;
  const user = await User.findOne({ user_name, password, user_type });
  if (!user) return res.json({ status: "fail" });
  res.json({ status: "success", user });
});

/* ================= CREATE DONATIONS ================= */
app.post("/addTrip", async (req, res) => {
  try {
    const pin = generatePIN();
    const trip = await Trip.create({
      ...req.body,
      otp: pin,
      otp_expiry: new Date(Date.now() + 60 * 60 * 1000)
    });
    res.json({ status: "success", trip_id: trip._id, pin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/addClothes", async (req, res) => {
  try {
    const pin = generatePIN();
    const trip = await Clothes.create({
      ...req.body,
      otp: pin,
      otp_expiry: new Date(Date.now() + 60 * 60 * 1000)
    });
    res.json({ status: "success", trip_id: trip._id, pin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});

/* ================= GET PENDING ================= */
app.get("/get-trips", async (_, res) => {
  const trips = await Trip.find({ status: "pending" }).sort({ createdAt: -1 });
  res.json(trips);
});

app.get("/get-clothes-trips", async (_, res) => {
  const trips = await Clothes.find({ status: "pending" }).sort({ createdAt: -1 });
  res.json(trips);
});

/* ================= PICK TRIP ================= */
app.post("/pick-trip", async (req, res) => {
  const trip = await Trip.findOneAndUpdate(
    { _id: req.body.trip_id, status: "pending" },
    { status: "picked" },
    { new: true }
  );
  if (!trip) return res.json({ status: "fail" });
  res.json({ status: "success", pin: trip.otp });
});

app.post("/pick-clothes-trip", async (req, res) => {
  const trip = await Clothes.findOneAndUpdate(
    { _id: req.body.trip_id, status: "pending" },
    { status: "picked" },
    { new: true }
  );
  if (!trip) return res.json({ status: "fail" });
  res.json({ status: "success", pin: trip.otp });
});
/* ================= VERIFY PIN ================= */
app.post("/verify-pin", async (req, res) => {
  try {
    const { trip_id, rider_id, pin } = req.body;

    let trip = await Trip.findById(trip_id);
    let type = "food";

    if (!trip) {
      trip = await Clothes.findById(trip_id);
      type = "clothes";
    }

    if (!trip) {
      return res.json({ status: "not_found" });
    }

    if (
      trip.status !== "picked" ||
      String(trip.rider_id) !== String(rider_id)
    ) {
      return res.json({ status: "not_allowed" });
    }

    if (trip.otp !== pin) {
      return res.json({ status: "invalid" });
    }

    trip.status = "completed";
    trip.otp = null;
    trip.otp_expiry = null;
    await trip.save();

    res.json({ status: "success", type });
  } catch (err) {
    console.error("Verify PIN error:", err);
    res.status(500).json({ status: "error" });
  }
});

/* ================= CHECK STATUS ================= */
app.get("/check-trip-status/:id", async (req, res) => {
  let trip = await Trip.findById(req.params.id);
  if (!trip) trip = await Clothes.findById(req.params.id);
  if (!trip)
    return res.json({ status: "not_found", trip_status: "not_found" });

  res.json({ status: "success", trip_status: trip.status });
});

/* ================= START ================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(`🔥 Server running on port ${PORT}`)
);
