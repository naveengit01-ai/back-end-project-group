require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(cors());

// ================= UPLOADS =================
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}
app.use("/uploads", express.static(UPLOADS_DIR));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// ================= DB CONNECT =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// ================= SCHEMAS =================
const UserSchema = new mongoose.Schema({
  firstname: String,
  lastname: String,
  address: String,
  email: String,
  ph_no: String,
  profile_photo: String,
  user_name: { type: String, unique: true },
  password: String,
  user_type: String
}, { timestamps: true });

const TripSchema = new mongoose.Schema({
  user_id: mongoose.Schema.Types.ObjectId,
  rider_id: mongoose.Schema.Types.ObjectId,
  food_type: String,
  quantity: Number,
  price: Number,
  provider_type: String,
  location: String,
  status: { type: String, default: "pending" },
  otp: String,
  otp_expiry: Date,
  rejection_reason: String
}, { timestamps: true });

const ClothesSchema = new mongoose.Schema({
  user_id: mongoose.Schema.Types.ObjectId,
  rider_id: mongoose.Schema.Types.ObjectId,
  cloth_type: String,
  quantity: Number,
  cloth_condition: String,
  location: String,
  status: { type: String, default: "pending" },
  otp: String,
  otp_expiry: Date
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);
const Trip = mongoose.model("Trip", TripSchema);
const Clothes = mongoose.model("Clothes", ClothesSchema);

// ================= UTIL =================
function generatePIN() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let pin = "";
  for (let i = 0; i < 6; i++) {
    pin += chars[Math.floor(Math.random() * chars.length)];
  }
  return pin;
}

// ================= SIGNUP =================
app.post("/signup", upload.single("profile_photo"), async (req, res) => {
  try {
    const exists = await User.findOne({ user_name: req.body.user_name });
    if (exists) return res.send({ status: "exists" });

    const user = await User.create({
      ...req.body,
      profile_photo: req.file ? `/uploads/${req.file.filename}` : null
    });

    res.send({ status: "success", user_id: user._id });
  } catch (err) {
    console.error(err);
    res.status(500).send({ status: "error" });
  }
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  const { user_name, password, user_type } = req.body;
  const user = await User.findOne({ user_name, password, user_type });
  if (!user) return res.send({ status: "fail" });
  res.send({ status: "success", user });
});

// ================= ADD FOOD TRIP =================
app.post("/addTrip", async (req, res) => {
  const pin = generatePIN();
  const trip = await Trip.create({
    ...req.body,
    otp: pin,
    otp_expiry: new Date(Date.now() + 60 * 60 * 1000)
  });

  res.send({ status: "success", trip_id: trip._id, pin });
});

// ================= ADD CLOTHES =================
app.post("/addClothes", async (req, res) => {
  const pin = generatePIN();
  const trip = await Clothes.create({
    user_id: req.body.user_id,
    cloth_type: req.body.cloth_type,
    quantity: req.body.quantity,
    cloth_condition: req.body.condition,
    location: req.body.location,
    otp: pin,
    otp_expiry: new Date(Date.now() + 60 * 60 * 1000)
  });

  res.send({ status: "success", trip_id: trip._id, pin });
});

// ================= GET PENDING =================
app.get("/get-trips", async (_, res) => {
  res.send(await Trip.find({ status: "pending" }).sort({ createdAt: -1 }));
});

app.get("/get-clothes-trips", async (_, res) => {
  res.send(await Clothes.find({ status: "pending" }).sort({ createdAt: -1 }));
});

// ================= PICK TRIP =================
app.post("/pick-trip", async (req, res) => {
  const trip = await Trip.findOneAndUpdate(
    { _id: req.body.trip_id, status: "pending" },
    { status: "picked", rider_id: req.body.rider_id },
    { new: true }
  );

  if (!trip) return res.send({ status: "fail" });
  res.send({ status: "success", pin: trip.otp });
});

app.post("/pick-clothes-trip", async (req, res) => {
  const trip = await Clothes.findOneAndUpdate(
    { _id: req.body.trip_id, status: "pending" },
    { status: "picked", rider_id: req.body.rider_id },
    { new: true }
  );

  if (!trip) return res.send({ status: "fail" });
  res.send({ status: "success", pin: trip.otp });
});

// ================= VERIFY PIN =================
app.post("/verify-pin", async (req, res) => {
  const { trip_id, rider_id, pin } = req.body;

  let trip = await Trip.findById(trip_id);
  let type = "trips";

  if (!trip) {
    trip = await Clothes.findById(trip_id);
    type = "clothes";
  }
  if (!trip) return res.send({ status: "not_found" });

  if (trip.status !== "picked" || String(trip.rider_id) !== String(rider_id))
    return res.send({ status: "not_allowed" });

  if (Date.now() > new Date(trip.otp_expiry).getTime())
    return res.send({ status: "expired" });

  if (trip.otp !== pin)
    return res.send({ status: "invalid" });

  trip.status = "completed";
  trip.otp = null;
  trip.otp_expiry = null;
  await trip.save();

  res.send({ status: "success", type });
});

// ================= CHECK TRIP STATUS =================
app.get("/check-trip-status/:trip_id", async (req, res) => {
  let trip = await Trip.findById(req.params.trip_id);

  if (!trip) {
    trip = await Clothes.findById(req.params.trip_id);
  }

  if (!trip) {
    return res.status(404).json({
      status: "not_found",
      trip_status: "not_found"
    });
  }

  res.json({
    status: "success",
    trip_status: trip.status
  });
});

// ================= MY DATA =================
app.get("/my-donations/:user_id", async (req, res) => {
  res.send(await Trip.find({ user_id: req.params.user_id }));
});

app.get("/my-clothes-donations/:user_id", async (req, res) => {
  res.send(await Clothes.find({ user_id: req.params.user_id }));
});

app.get("/my-trips/:rider_id", async (req, res) => {
  res.send(await Trip.find({ rider_id: req.params.rider_id }));
});

app.get("/my-clothes-trips/:rider_id", async (req, res) => {
  res.send(await Clothes.find({ rider_id: req.params.rider_id }));
});

// ================= SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🔥 Server running on port ${PORT}`)
);
