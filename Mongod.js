require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const User = require("./models/User");
const Donation = require("./models/Donation");
const Advertisement = require("./models/Advertisement");
const Job = require("./models/Job");
const JobApplication = require("./models/JobApplication");
const Notification = require("./models/Notification");

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

/* ================= EMAIL (BREVO) ================= */
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const sendOTP = async (email, otp) => {
  try {
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { name: "DWJD", email: "naveengit01@gmail.com" },
        to: [{ email }],
        subject: "Your DWJD OTP",
        htmlContent: `
          <h2>DWJD Verification</h2>
          <h1>${otp}</h1>
          <p>Valid for 10 minutes</p>
        `
      },
      {
        headers: {
          "api-key": process.env.BREVO_API_KEY,
          "Content-Type": "application/json"
        }
      }
    );
  } catch (err) {
    console.error("❌ OTP Email Error:", err.message);
  }
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

    if (!username || !first_name || !last_name || !phone || !email ||
        !user_type || !password || !confirm_password)
      return res.json({ status: "missing_fields" });

    if (password !== confirm_password)
      return res.json({ status: "password_mismatch" });

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      if (existingUser.is_verified)
        return res.json({ status: "user_exists" });

      const otp = generateOTP();
      existingUser.otp = otp;
      existingUser.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
      await existingUser.save();
      await sendOTP(email, otp);
      return res.json({ status: "otp_resent" });
    }

    const otp = generateOTP();
    const hashedPassword = await bcrypt.hash(password, 10);

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
      if (!latitude || !longitude)
        return res.json({ status: "location_required" });

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

/* ================= VERIFY OTP ================= */
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.json({ status: "not_found" });
  if (user.is_verified) return res.json({ status: "already_verified" });
  if (Date.now() > user.otp_expiry) return res.json({ status: "otp_expired" });
  if (user.otp !== otp) return res.json({ status: "invalid_otp" });

  user.is_verified = true;
  user.otp = null;
  user.otp_expiry = null;
  await user.save();

  res.json({ status: "account_verified" });
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  const { email, password, user_type } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.json({ status: "invalid_credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ status: "invalid_credentials" });

  if (user.user_type !== "admin") {
    if (user.user_type !== user_type)
      return res.json({ status: "invalid_credentials" });
    if (!user.is_verified)
      return res.json({ status: "email_not_verified" });
  }

  const token = jwt.sign(
    { userId: user._id, role: user.user_type },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ status: "login_success", token, user });
});

/* ================= DONATION ================= */
app.post("/donate", async (req, res) => {
  const otp = generateOTP();
  const donation = await Donation.create({
    ...req.body,
    otp,
    otp_expiry: new Date(Date.now() + 10 * 60 * 1000)
  });

  await sendOTP(req.body.donor_email, otp);
  res.json({ status: "otp_sent", donation_id: donation._id });
});

app.post("/verify-donate-otp", async (req, res) => {
  const donation = await Donation.findById(req.body.donation_id);
  if (!donation) return res.json({ status: "not_found" });
  if (donation.otp !== req.body.otp)
    return res.json({ status: "invalid_otp" });

  donation.is_verified = true;
  donation.otp = null;
  donation.otp_expiry = null;
  await donation.save();

  res.json({ status: "donation_verified" });
});

/* ================= RIDER ================= */
app.post("/rider/pickup", async (req, res) => {
  const donation = await Donation.findById(req.body.donation_id);
  donation.rider_email = req.body.rider_email;
  donation.donation_status = "picked";
  await donation.save();
  res.json({ status: "pickup_locked" });
});

app.post("/rider/mark-delivered", async (req, res) => {
  const donation = await Donation.findById(req.body.donation_id);
  donation.donation_status = "delivered";
  await donation.save();
  res.json({ status: "delivered_success" });
});

/* ================= ADS ================= */
app.post("/admin/add-advertisement", async (req, res) => {
  const ad = await Advertisement.create(req.body);
  res.json({ status: "advertisement_added", ad });
});

app.get("/advertisements", async (req, res) => {
  const ads = await Advertisement.find();
  res.json({ status: "success", ads });
});

/* ================= CAREER / JOB ================= */
app.post("/admin/add-job", async (req, res) => {
  const job = await Job.create(req.body);
  res.json({ status: "job_added", job });
});

app.get("/jobs", async (req, res) => {
  const jobs = await Job.find({ is_active: true });
  res.json({ status: "success", jobs });
});

app.post("/apply-job", async (req, res) => {
  const job = await Job.findById(req.body.job_id);
  if (!job) return res.json({ status: "job_not_found" });

  const application = await JobApplication.create({
    ...req.body,
    job_title: job.title
  });

  await Notification.create({
    type: "job_application",
    message: `New application for ${job.title}`,
    related_id: application._id
  });

  res.json({ status: "application_submitted" });
});

/* ================= ADMIN JOB NOTIFICATIONS ================= */
app.get("/admin/job-applications", async (req, res) => {
  const applications = await JobApplication.find()
    .sort({ createdAt: -1 });
  res.json({ status: "success", applications });
});

/* ================= INTERVIEW EMAIL ================= */
const sendInterviewEmail = async ({ to, name, role }) => {
  await axios.post(
    "https://api.brevo.com/v3/smtp/email",
    {
      sender: { name: "DWJD HR", email: "naveengit01@gmail.com" },
      to: [{ email: to }],
      subject: "Interview Call – DWJD",
      htmlContent: `
        <p>Dear ${name},</p>
        <p>You are shortlisted for <b>${role}</b>.</p>
        <p>DWJD Recruitment Team</p>
      `
    },
    { headers: { "api-key": process.env.BREVO_API_KEY } }
  );
};

app.post("/admin/job-application/accept", async (req, res) => {
  const appData = await JobApplication.findById(req.body.application_id);
  appData.status = "accepted";
  await appData.save();

  await sendInterviewEmail({
    to: appData.email,
    name: appData.first_name,
    role: appData.job_title
  });

  res.json({ status: "accepted" });
});

/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
