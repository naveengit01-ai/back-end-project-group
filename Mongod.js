require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://back-end-project-group.onrender.com"
  ],
  credentials: true
}));

/* ================= HEALTH ================= */
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

/* ================= UPLOAD ================= */
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }
});

/* ================= DB ================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error(err);
    process.exit(1);
  });

/* ================= MODELS ================= */
const User = mongoose.model("User", new mongoose.Schema({
  firstname: String,
  lastname: String,
  address: String,
  email: String,
  ph_no: String,
  user_name: String,
  password: String,
  user_type: String,
  profile_photo: String
}, { timestamps: true }));

const Trip = mongoose.model("Trip", new mongoose.Schema({
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
}, { timestamps: true }));

const Clothes = mongoose.model("Clothes", new mongoose.Schema({
  user_id: mongoose.Schema.Types.ObjectId,
  rider_id: mongoose.Schema.Types.ObjectId,
  cloth_type: String,
  quantity: Number,
  cloth_condition: String,
  location: String,
  status: { type: String, default: "pending" },
  otp: String,
  otp_expiry: Date
}, { timestamps: true }));

/* ================= ROUTES ================= */

// SIGNUP
app.post("/signup", upload.single("profile_photo"), async (req, res) => {
  const exists = await User.findOne({ user_name: req.body.user_name });
  if (exists) return res.json({ status: "exists" });

  await User.create({
    ...req.body,
    profile_photo: req.file ? `/uploads/${req.file.filename}` : null
  });

  res.json({ status: "success" });
});

// LOGIN
app.post("/login", async (req, res) => {
  const user = await User.findOne(req.body);
  if (!user) return res.json({ status: "fail" });
  res.json({ status: "success", user });
});

// GET TRIPS (🔥 THIS WAS MISSING)
app.get("/get-trips", async (_, res) => {
  const trips = await Trip.find({ status: "pending" });
  res.json(trips);
});

app.get("/get-clothes-trips", async (_, res) => {
  const trips = await Clothes.find({ status: "pending" });
  res.json(trips);
});

// PICK TRIP
app.post("/pick-trip", async (req, res) => {
  const trip = await Trip.findOneAndUpdate(
    { _id: req.body.trip_id, status: "pending" },
    { status: "picked" },
    { new: true }
  );
  if (!trip) return res.json({ status: "fail" });
  res.json({ status: "success", pin: trip.otp });
});
app.get("/__test__", (req, res) => {
  res.send("TEST ROUTE WORKING");
});


/* ================= START ================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🔥 Server running on ${PORT}`));
