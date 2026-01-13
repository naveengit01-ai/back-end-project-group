require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Resend } = require("resend");

const User = require("./models/User");
const Donation = require("./models/Donation");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(cors());

/* ================= DATABASE ================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

/* ================= RESEND SETUP ================= */
const resend = new Resend(process.env.RESEND_API_KEY);
console.log("RESEND KEY LOADED:", !!process.env.RESEND_API_KEY);

/* ================= HELPERS ================= */
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

/* ================= SEND OTP ================= */
const sendOTP = async (email, otp) => {
  try {
    const { data, error } = await resend.emails.send({
      from: "DWJD <onboarding@resend.dev>", // free tier allowed
      to: [email], // 🔥 MUST BE ARRAY
      subject: "Your DWJD OTP",
      html: `
        <div style="font-family:Arial,sans-serif">
          <h2>DWJD Verification</h2>
          <p>Your OTP is:</p>
          <h1 style="letter-spacing:4px">${otp}</h1>
          <p>This OTP is valid for 10 minutes.</p>
        </div>
      `
    });

    if (error) {
      console.error("❌ RESEND ERROR:", error);
    } else {
      console.log("✅ OTP email sent. Resend ID:", data.id);
    }
  } catch (err) {
    console.error("❌ OTP SEND FAILED (CATCH):", err);
  }
};


/* ================= HEALTH ================= */
app.get("/health", (_, res) => res.send("OK"));

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {
  try {
    const {
      username,
      first_name,
      last_name,
      phone,
      email,
      user_type,
      password,
      confirm_password,
      latitude,
      longitude
    } = req.body;

    if (
      !username ||
      !first_name ||
      !last_name ||
      !phone ||
      !email ||
      !user_type ||
      !password ||
      !confirm_password
    ) {
      return res.json({ status: "missing_fields" });
    }

    if (username.length < 6) {
      return res.json({ status: "invalid_username" });
    }

    if (await User.findOne({ username })) {
      return res.json({ status: "username_exists" });
    }

    if (await User.findOne({ email })) {
      return res.json({ status: "user_exists" });
    }

    if (password !== confirm_password) {
      return res.json({ status: "password_mismatch" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    const userData = {
      username,
      first_name,
      last_name,
      phone,
      email,
      user_type,
      password: hashedPassword,
      otp,
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
      is_verified: false
    };

    if (user_type === "rider") {
      if (!latitude || !longitude) {
        return res.json({ status: "location_required" });
      }
      userData.rider_location = {
        lat: Number(latitude),
        lng: Number(longitude)
      };
    }

    await User.create(userData);

    // NON-BLOCKING OTP SEND
    sendOTP(email, otp);

    res.json({ status: "signup_success_otp_sent" });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({ status: "error" });
  }
});

/* ================= VERIFY USER OTP ================= */
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ status: "not_found" });

  if (user.is_verified) {
    return res.json({ status: "already_verified" });
  }

  if (Date.now() > user.otp_expiry) {
    return res.json({ status: "otp_expired" });
  }

  if (user.otp !== otp) {
    return res.json({ status: "invalid_otp" });
  }

  user.is_verified = true;
  user.otp = null;
  user.otp_expiry = null;
  await user.save();

  res.json({ status: "account_verified" });
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  const { email, password, user_type } = req.body;

  const user = await User.findOne({ email, user_type });
  if (!user) return res.json({ status: "invalid_credentials" });
  if (!user.is_verified) return res.json({ status: "email_not_verified" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ status: "invalid_credentials" });

  const token = jwt.sign(
    { userId: user._id, role: user.user_type },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    status: "login_success",
    token,
    user: {
      email: user.email,
      first_name: user.first_name,
      user_type: user.user_type
    }
  });
});

/* ================= DONATE ================= */
app.post("/donate", async (req, res) => {
  const {
    donor_email,
    donor_name,
    item_type,
    item_name,
    quantity,
    price_type,
    price_amount,
    pickup_location,
    remarks
  } = req.body;

  if (
    !donor_email ||
    !donor_name ||
    !item_type ||
    !item_name ||
    !quantity ||
    !price_type ||
    !pickup_location
  ) {
    return res.json({ status: "missing_fields" });
  }

  let finalPrice = 0;
  if (price_type === "paid") {
    if (!price_amount || price_amount <= 0) {
      return res.json({ status: "invalid_price" });
    }
    finalPrice = Number(price_amount);
  }

  const otp = generateOTP();

  const donation = await Donation.create({
    donor_email,
    donor_name,
    item_type,
    item_name,
    quantity,
    price_type,
    price_amount: finalPrice,
    pickup_location,
    remarks,
    donation_status: "not_picked",
    otp,
    otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
    is_verified: false
  });

  sendOTP(donor_email, otp);

  res.json({ status: "otp_sent", donation_id: donation._id });
});

/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
