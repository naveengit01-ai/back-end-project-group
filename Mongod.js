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

/* ================= UTILITIES ================= */
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

/* ================= EMAIL HELPERS ================= */

/* OTP EMAIL */
const sendOTP = async (email, otp) => {
  try {
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { name: "DWJD", email: "naveengit01@gmail.com" },
        to: [{ email }],
        subject: "DWJD Email Verification",
        htmlContent: `
          <div style="font-family:Arial">
            <h2>DWJD Verification</h2>
            <p>Your OTP:</p>
            <h1 style="letter-spacing:4px">${otp}</h1>
            <p>Valid for 10 minutes</p>
          </div>
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

/* INTERVIEW ACCEPT EMAIL */
const sendInterviewAcceptEmail = async ({
  to,
  candidateName,
  jobTitle,
  date,
  time,
  mode,
  location
}) => {
  await axios.post(
    "https://api.brevo.com/v3/smtp/email",
    {
      sender: {
        name: "DWJD Recruitment Team",
        email: "naveengit01@gmail.com"
      },
      to: [{ email: to }],
      subject: `Interview Invitation – ${jobTitle}`,
      htmlContent: `
        <div style="font-family:Arial;line-height:1.6">
          <h2 style="color:#10b981">DWJD Interview Invitation</h2>

          <p>Dear <strong>${candidateName}</strong>,</p>

          <p>
            We are pleased to inform you that you have been
            <strong>shortlisted</strong> for the position of
            <strong>${jobTitle}</strong>.
          </p>

          <p><b>Interview Details:</b></p>
          <ul>
            <li><b>Date:</b> ${date}</li>
            <li><b>Time:</b> ${time}</li>
            <li><b>Mode:</b> ${mode}</li>
            <li><b>Location / Link:</b> ${location}</li>
          </ul>

          <p>Please reply to this email to confirm your availability.</p>

          <p>
            Regards,<br/>
            <strong>DWJD Recruitment Team</strong>
          </p>
        </div>
      `
    },
    {
      headers: {
        "api-key": process.env.BREVO_API_KEY,
        "Content-Type": "application/json"
      }
    }
  );
};

/* INTERVIEW REJECT EMAIL */
const sendInterviewRejectEmail = async ({
  to,
  candidateName,
  jobTitle
}) => {
  await axios.post(
    "https://api.brevo.com/v3/smtp/email",
    {
      sender: {
        name: "DWJD Recruitment Team",
        email: "naveengit01@gmail.com"
      },
      to: [{ email: to }],
      subject: `Application Update – ${jobTitle}`,
      htmlContent: `
        <div style="font-family:Arial;line-height:1.6">
          <h2 style="color:#ef4444">DWJD Application Update</h2>

          <p>Dear <strong>${candidateName}</strong>,</p>

          <p>
            Thank you for applying for the position of
            <strong>${jobTitle}</strong> at DWJD.
          </p>

          <p>
            After careful consideration, we regret to inform you that
            we will not be moving forward with your application at this time.
          </p>

          <p>
            We truly appreciate your interest in DWJD and encourage you
            to apply again in the future.
          </p>

          <p>
            Regards,<br/>
            <strong>DWJD Recruitment Team</strong>
          </p>
        </div>
      `
    },
    {
      headers: {
        "api-key": process.env.BREVO_API_KEY,
        "Content-Type": "application/json"
      }
    }
  );
};

/* ================= AUTH ================= */
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

    if (!username || !first_name || !last_name || !phone ||
        !email || !user_type || !password || !confirm_password)
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
  } catch (err) {
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

/* ================= JOBS ================= */
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

app.get("/admin/job-applications", async (req, res) => {
  const applications = await JobApplication.find().sort({ createdAt: -1 });
  res.json({ status: "success", applications });
});

/* ================= ACCEPT ================= */
app.post("/admin/job-application/accept", async (req, res) => {
  const appData = await JobApplication.findById(req.body.application_id);

  appData.status = "accepted";
  await appData.save();

  await sendInterviewAcceptEmail({
    to: appData.email,
    candidateName: appData.first_name,
    jobTitle: appData.job_title,
    date: req.body.date,
    time: req.body.time,
    mode: req.body.mode,
    location: req.body.location
  });

  res.json({ status: "accepted" });
});

/* ================= REJECT ================= */
app.post("/admin/job-application/reject", async (req, res) => {
  const appData = await JobApplication.findById(req.body.application_id);

  appData.status = "rejected";
  await appData.save();

  await sendInterviewRejectEmail({
    to: appData.email,
    candidateName: appData.first_name,
    jobTitle: appData.job_title
  });

  res.json({ status: "rejected" });
});

/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
