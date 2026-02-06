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
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://back-end-project-group.onrender.com"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
  })
);


/* ================= DATABASE ================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

/* ================= UTIL ================= */
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

/* ================= EMAIL CORE ================= */
const sendEmail = async ({ to, subject, html }) => {
  await axios.post(
    "https://api.brevo.com/v3/smtp/email",
    {
      sender: { name: "DWJD", email: "naveengit01@gmail.com" },
      to: [{ email: to }],
      subject,
      htmlContent: html
    },
    {
      headers: {
        "api-key": process.env.BREVO_API_KEY,
        "Content-Type": "application/json"
      }
    }
  );
};

/* ================= OTP EMAIL ================= */
const sendOTP = async (email, otp) => {
  await sendEmail({
    to: email,
    subject: "DWJD Email Verification",
    html: `
      <h2>DWJD Verification</h2>
      <h1>${otp}</h1>
      <p>Valid for 10 minutes</p>
    `
  });
};

/* ================= INTERVIEW EMAIL ================= */
const sendInterviewAcceptEmail = async ({
  to,
  name,
  job,
  date,
  time,
  mode,
  location
}) => {
  await sendEmail({
    to,
    subject: `Interview Invitation – ${job}`,
    html: `
      <p>Dear ${name},</p>
      <p>You are shortlisted for <b>${job}</b>.</p>
      <ul>
        <li>Date: ${date}</li>
        <li>Time: ${time}</li>
        <li>Mode: ${mode}</li>
        <li>Location: ${location}</li>
      </ul>
      <p>Please reply to confirm availability.</p>
    `
  });
};

/* =================================================
   AUTH
================================================= */

app.post("/signup", async (req, res) => {
  try {
    const {
      username, first_name, last_name, phone,
      email, user_type, password, confirm_password,
      latitude, longitude
    } = req.body;

    if (!username || !first_name || !last_name ||
        !phone || !email || !user_type ||
        !password || !confirm_password)
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
      userData.rider_location = {
        lat: Number(latitude),
        lng: Number(longitude)
      };
    }

    await User.create(userData);
    await sendOTP(email, otp);

    res.json({ status: "signup_success_otp_sent" });
  } catch {
    res.status(500).json({ status: "error" });
  }
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.json({ status: "not_found" });
  if (user.is_verified) return res.json({ status: "already_verified" });
  if (user.otp !== otp) return res.json({ status: "invalid_otp" });

  user.is_verified = true;
  user.otp = null;
  user.otp_expiry = null;
  await user.save();

  res.json({ status: "account_verified" });
});

app.post("/login", async (req, res) => {
  const { email, password, user_type } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.json({ status: "invalid_credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ status: "invalid_credentials" });

  if (user.user_type !== "admin") {
    if (!user.is_verified || user.user_type !== user_type)
      return res.json({ status: "invalid_credentials" });
  }

  const token = jwt.sign(
    { id: user._id, role: user.user_type },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ status: "login_success", token, user });
});

/* =================================================
   DONATION + MY REQUESTS
================================================= */

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

app.post("/my-requests", async (req, res) => {
  const requests = await Donation.find({ donor_email: req.body.email });
  res.json({ status: "success", requests });
});

/* =================================================
   JOBS
================================================= */

app.post("/admin/add-job", async (req, res) => {
  const { title, description } = req.body;

  if (!title || !description) {
    return res.json({ status: "missing_fields" });
  }

  const job = await Job.create({
    title,
    description,
    is_active: true
  });

  res.json({ status: "job_added", job });
});


app.get("/jobs", async (req, res) => {
  const jobs = await Job.find({ is_active: true });
  res.json({ status: "success", jobs });
});

app.post("/apply-job", async (req, res) => {
  try {
    const {
      job_id,
      first_name,
      last_name,
      email,
      phone,
      location,
      resume_link,
      message
    } = req.body;

    // 1️⃣ Validate basics
    if (!job_id || !first_name || !last_name || !email || !phone || !location) {
      return res.json({ status: "missing_fields" });
    }

    // 2️⃣ Fetch job created by admin
    const job = await Job.findById(job_id);
    if (!job) {
      return res.json({ status: "job_not_found" });
    }
    const alreadyApplied = await JobApplication.findOne({
  job_id,
  email
});

if (alreadyApplied) {
  return res.json({ status: "already_applied" });
}
    // 3️⃣ Create application WITH job_title injected
    const application = await JobApplication.create({
      job_id,
      job_title: job.title,   // ✅ THIS IS THE FIX
      first_name,
      last_name,
      email,
      phone,
      location,
      resume_link,
      message,
      status: "pending"
    });

    // 4️⃣ Notify admin
    await Notification.create({
      type: "job_application",
      message: `New application for ${job.title}`,
      related_id: application._id
    });

    res.json({ status: "application_submitted" });

  } catch (err) {
    console.error("Apply job error:", err);
    res.status(500).json({ status: "error" });
  }
});


app.get("/admin/job-applications", async (req, res) => {
  const applications = await JobApplication.find().sort({ createdAt: -1 });
  res.json({ status: "success", applications });
});

/* =================================================
   INTERVIEW FLOW
================================================= */

app.post("/admin/interview/schedule", async (req, res) => {
  const { application_id, date, time, mode, location } = req.body;

  if (!application_id || !date || !time || !mode || !location) {
    return res.json({ status: "missing_fields" });
  }

  const appData = await JobApplication.findById(application_id);
  if (!appData) return res.json({ status: "not_found" });

  appData.status = "interview_scheduled";
  appData.interview = { date, time, mode, location };
  await appData.save();

  await sendInterviewAcceptEmail({
    to: appData.email,
    name: appData.first_name,
    job: appData.job_title,
    date,
    time,
    mode,
    location
  });

  res.json({ status: "interview_scheduled" });
});

app.post("/admin/interview/reject", async (req, res) => {
  const appData = await JobApplication.findById(req.body.application_id);
  if (!appData) return res.json({ status: "not_found" });

  appData.status = "rejected";
  await appData.save();

  await sendEmail({
    to: appData.email,
    subject: "Application Update – DWJD",
    html: `<p>Thank you for applying. We won’t proceed further.</p>`
  });

  res.json({ status: "rejected" });
});

app.post("/admin/interview/select", async (req, res) => {
  const { application_id, username, password, user_type } = req.body;

  const appData = await JobApplication.findById(application_id);
  if (!appData) return res.json({ status: "not_found" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const otp = generateOTP();

  await User.create({
    username,
    first_name: appData.first_name,
    last_name: appData.last_name,
    phone: appData.phone,
    email: appData.email,
    user_type,
    password: hashedPassword,
    otp,
    otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
    is_verified: false
  });

  appData.status = "selected";
  await appData.save();

  await sendOTP(appData.email, otp);

  res.json({ status: "account_created_otp_sent" });
});

app.post("/rider/pickup", async (req, res) => {
  const donation = await Donation.findById(req.body.donation_id);
  if (!donation) return res.json({ status: "not_found" });

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

app.post("/rider/available-pickups", async (req, res) => {
  const donations = await Donation.find({ donation_status: "not_picked" });
  res.json({ status: "success", donations });
});

/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
