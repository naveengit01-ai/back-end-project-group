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
  .then(() => console.log("✅ MongoDB Connected sucess"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

/* ================= EMAIL ================= */
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const sendOTP = async (email, otp) => {
  await mailer.sendMail({
    from: `"DWJD Support" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "DWJD OTP",
    html: `<h2>Your OTP</h2><h1>${otp}</h1>`
  });
};

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
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000)
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
    await sendOTP(email, otp);

    res.json({ status: "signup_success_otp_sent" });
  } catch (err) {
    console.error(err);
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
    otp,
    otp_expiry: new Date(Date.now() + 10 * 60 * 1000)
  });

  await sendOTP(donor_email, otp);

  res.json({ status: "otp_sent", donation_id: donation._id });
});

/* ================= RIDER PICKUP (LOCK) ================= */
app.post("/rider/pickup", async (req, res) => {
  const { donation_id, rider_email } = req.body;

  const donation = await Donation.findById(donation_id);
  if (!donation) return res.json({ status: "not_found" });

  if (donation.donation_status !== "not_picked") {
    return res.json({ status: "already_taken" });
  }

  donation.rider_email = rider_email;
  donation.donation_status = "picked";
  donation.picked_at = new Date();

  await donation.save();
  res.json({ status: "pickup_locked", donation });
});

/* ================= VERIFY DONATION OTP ================= */
app.post("/verify-donate-otp", async (req, res) => {
  const { donation_id, otp, rider_email } = req.body;

  const donation = await Donation.findById(donation_id);
  if (!donation) return res.json({ status: "not_found" });

  if (donation.is_verified) {
    return res.json({ status: "already_verified" });
  }

  if (donation.otp !== otp) {
    return res.json({ status: "invalid_otp" });
  }

  donation.is_verified = true;
  donation.rider_email = rider_email;
  donation.otp = null;
  donation.otp_expiry = null;

  await donation.save();
  res.json({ status: "donation_verified_and_picked" });
});

/* ================= REJECT PICKUP ================= */
app.post("/rider/reject-pickup", async (req, res) => {
  const { donation_id, rider_email, reason } = req.body;

  const donation = await Donation.findOne({
    _id: donation_id,
    rider_email
  });

  if (!donation) {
    return res.json({ status: "invalid_request" });
  }

  donation.donation_status = "not_picked";
  donation.rider_email = null;
  donation.rejection_reason = reason;

  await donation.save();
  res.json({ status: "pickup_rejected" });
});

/* ================= MARK DELIVERED ================= */
app.post("/rider/mark-delivered", async (req, res) => {
  const { donation_id, rider_email } = req.body;

  const donation = await Donation.findOne({
    _id: donation_id,
    rider_email,
    donation_status: "picked"
  });

  if (!donation) return res.json({ status: "invalid_request" });

  donation.donation_status = "delivered";
  donation.delivered_at = new Date();
  await donation.save();

  res.json({ status: "delivered_success" });
});

/* ================= MY RIDES ================= */
app.post("/rider/my-rides", async (req, res) => {
  const { rider_email } = req.body;

  const rides = await Donation.find({
    rider_email,
    donation_status: { $in: ["picked", "delivered"] }
  }).sort({ updatedAt: -1 });

  res.json({ status: "success", rides });
});

/* ================= AVAILABLE PICKUPS ================= */
app.post("/rider/available-pickups", async (req, res) => {
  const donations = await Donation.find({
    donation_status: "not_picked"
  }).sort({ createdAt: -1 });

  res.json({ status: "success", donations });
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


/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
