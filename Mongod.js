require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const cors = require("cors");
const jwt = require("jsonwebtoken");


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

/* ================= EMAIL SETUP ================= */
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
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const isStrongPassword = pwd =>
  /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(pwd);

const sendOTP = async (email, otp) => {
  await mailer.sendMail({
    from: `"DWJD Support" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "DWJD Email Verification OTP",
    html: `
      <h2>Email Verification</h2>
      <p>Your OTP is : </p>
      <u><h1>${otp}</h1></u>
      <p>This OTP is valid for 10 minutes.</p>
    `
  });
};

/* ================= SIGNUP API ================= */
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

    /* ---------- BASIC VALIDATION ---------- */
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

    /* ---------- USERNAME VALIDATION ---------- */
    if (username.length < 6) {
      return res.json({ status: "invalid_username" });
    }

    const usernameExists = await User.findOne({ username });
    if (usernameExists) {
      return res.json({ status: "username_exists" });
    }

    /* ---------- EMAIL CHECK ---------- */
    const emailExists = await User.findOne({ email });
    if (emailExists) {
      return res.json({ status: "user_exists" });
    }

    /* ---------- PASSWORD CHECK ---------- */
    if (password !== confirm_password) {
      return res.json({ status: "password_mismatch" });
    }

    /* ---------- HASH PASSWORD ---------- */
    const hashedPassword = await bcrypt.hash(password, 10);

    /* ---------- OTP ---------- */
    const otp = generateOTP();

    /* ---------- USER DATA ---------- */
    const userData = {
      username,
      first_name,
      last_name,
      phone,
      email,
      user_type,
      password: hashedPassword,
      otp,
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000)
    };

    /* ---------- RIDER LOCATION ---------- */
    if (user_type === "rider") {
      if (!latitude || !longitude) {
        return res.json({ status: "location_required" });
      }

      userData.rider_location = {
        lat: Number(latitude),
        lng: Number(longitude)
      };
    }

    /* ---------- SAVE USER ---------- */
    await User.create(userData);

    /* ---------- SEND OTP ---------- */
    await sendOTP(email, otp);

    return res.json({
      status: "signup_success_otp_sent"
    });

  } catch (err) {
    console.error("Signup Error:", err);
    return res.status(500).json({
      status: "error"
    });
  }
});

/* ================= VERIFY OTP ================= */
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ status: "not_found" });

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

/* ================= LOGIN API ================= */
app.post("/login", async (req, res) => {
  try {
    const { email, password, user_type } = req.body;

    // basic validation
    if (!email || !password || !user_type) {
      return res.json({ status: "missing_fields" });
    }

    // check user
    const user = await User.findOne({ email, user_type });
    if (!user) {
      return res.json({ status: "invalid_credentials" });
    }

    // check email verified
    if (!user.is_verified) {
      return res.json({ status: "email_not_verified" });
    }

    // check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ status: "invalid_credentials" });
    }

    // generate JWT
    const token = jwt.sign(
      {
        userId: user._id,
        role: user.user_type
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES }
    );

    res.json({
      status: "login_success",
      token,
      user: {
        id: user._id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        user_type: user.user_type
      }
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ status: "error" });
  }
});
/* ================= GET USER BY EMAIL ================= */
app.post("/get-user-by-email", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ status: "email_required" });
    }

    const user = await User.findOne({ email }).select(
      "-password -otp -otp_expiry"
    );

    if (!user) {
      return res.json({ status: "not_found" });
    }

    res.json({
      status: "success",
      user
    });
  } catch (err) {
    console.error("Get User Error:", err);
    res.status(500).json({ status: "error" });
  }
});
/* ================= UPDATE USER PROFILE BY EMAIL ================= */
app.put("/update-profile", async (req, res) => {
  try {
    const { email, first_name, last_name, phone } = req.body;

    if (!email) {
      return res.json({ status: "email_required" });
    }

    const updateData = {};

    if (first_name) updateData.first_name = first_name;
    if (last_name) updateData.last_name = last_name;
    if (phone) updateData.phone = phone;

    if (Object.keys(updateData).length === 0) {
      return res.json({ status: "nothing_to_update" });
    }

    const user = await User.findOneAndUpdate(
      { email },
      { $set: updateData },
      { new: true }
    ).select("-password -otp -otp_expiry");

    if (!user) {
      return res.json({ status: "not_found" });
    }

    res.json({
      status: "updated_successfully",
      user
    });
  } catch (err) {
    console.error("Update Profile Error:", err);
    res.status(500).json({ status: "error" });
  }
});
/* ================= DONATE ITEM (SEND OTP) ================= */
app.post("/donate", async (req, res) => {
  try {
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

    // BASIC VALIDATION
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

    if (Number(quantity) <= 0) {
      return res.json({ status: "invalid_quantity" });
    }

    // SAFE PRICE HANDLING
    let finalPrice = 0;
    if (price_type === "paid") {
      if (!price_amount || Number(price_amount) <= 0) {
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
      quantity: Number(quantity),
      price_type,
      price_amount: finalPrice,
      pickup_location,
      remarks,
      donation_status: "not_picked",
      otp,
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
      is_verified: false
    });

    // OTP EMAIL (FAIL SAFE)
    try {
      await sendOTP(donor_email, otp);
    } catch (mailErr) {
      console.error("OTP Mail Failed:", mailErr.message);
    }

    return res.json({
      status: "otp_sent",
      donation_id: donation._id
    });

  } catch (err) {
    console.error("🔥 DONATE API ERROR:", err);
    return res.status(500).json({
      status: "error",
      message: err.message
    });
  }
});
/* ================= VERIFY DONATION OTP ================= */
app.post("/verify-donate-otp", async (req, res) => {
  try {
    const { donation_id, otp } = req.body;

    if (!donation_id || !otp) {
      return res.json({ status: "missing_fields" });
    }

    const donation = await Donation.findById(donation_id);
    if (!donation) {
      return res.json({ status: "not_found" });
    }

    if (Date.now() > donation.otp_expiry) {
      return res.json({ status: "otp_expired" });
    }

    if (donation.otp !== otp) {
      return res.json({ status: "invalid_otp" });
    }

    donation.is_verified = true;
    donation.donation_status = "picked"; // 🔥 STATUS UPDATED
    donation.otp = null;
    donation.otp_expiry = null;
    await donation.save();

    res.json({
      status: "donation_verified_and_picked",
      donation
    });
  } catch (err) {
    console.error("Verify Donation OTP Error:", err);
    res.status(500).json({ status: "error" });
  }
});
/* ================= MY REQUESTS (USER SIDE) ================= */
app.post("/my-requests", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ status: "email_required" });
    }

    const requests = await Donation.find({ donor_email: email })
      .sort({ createdAt: -1 }) // latest first
      .select(
        "item_type item_name quantity donation_status createdAt"
      );

    return res.json({
      status: "success",
      requests
    });

  } catch (err) {
    console.error("My Requests Error:", err);
    return res.status(500).json({
      status: "error",
      message: err.message
    });
  }
});

app.post("/rider/available-pickups", async (req, res) => {
  try {
    const donations = await Donation.find({
      donation_status: "not_picked"
    });

    res.json({
      status: "success",
      donations
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});

/* ================= RIDER AVAILABLE PICKUPS (NO LOCATION FILTER) ================= */
app.post("/rider/available-pickups", async (req, res) => {
  try {
    const donations = await Donation.find({
      donation_status: "not_picked"
    }).sort({ createdAt: -1 });

    res.json({
      status: "success",
      donations
    });
  } catch (err) {
    console.error("RIDER PICKUPS ERROR:", err);
    res.status(500).json({ status: "error" });
  }
});


/* ================= RESEND DONATION OTP ================= */
app.post("/resend-donate-otp", async (req, res) => {
  try {
    const { donation_id } = req.body;

    if (!donation_id) {
      return res.json({ status: "missing_fields" });
    }

    const donation = await Donation.findById(donation_id);
    if (!donation) {
      return res.json({ status: "not_found" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    donation.otp = otp;
    donation.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
    await donation.save();

    await sendOTP(donation.donor_email, otp);

    res.json({ status: "otp_resent" });
  } catch (err) {
    console.error("RESEND OTP ERROR:", err);
    res.status(500).json({ status: "error" });
  }
});

/* ================= RIDER MY DELIVERIES ================= */
app.post("/rider/my-deliveries", async (req, res) => {
  try {
    const { rider_email } = req.body;

    if (!rider_email) {
      return res.json({ status: "email_required" });
    }

    const deliveries = await Donation.find({
      rider_email: rider_email,
      donation_status: { $in: ["picked", "collected", "delivered"] }
    }).sort({ updatedAt: -1 });

    res.json({
      status: "success",
      deliveries
    });
  } catch (err) {
    console.error("RIDER MY DELIVERIES ERROR:", err);
    res.status(500).json({ status: "error" });
  }
});



/* ================= START SERVER ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
