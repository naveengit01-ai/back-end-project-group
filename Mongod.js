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
    const response = await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: {
          name: "DWJD",
          email: "naveengit01@gmail.com" // must be verified in Brevo
        },
        to: [{ email }],
        subject: "Your DWJD OTP",
        htmlContent: `
          <div style="font-family:Arial">
            <h2>DWJD Verification</h2>
            <p>Your OTP is:</p>
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

    console.log("✅ OTP sent:", response.data.messageId);
  } catch (err) {
    console.error("❌ Brevo Error:", err.response?.data || err.message);
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

    if (
      !username || !first_name || !last_name ||
      !phone || !email || !user_type ||
      !password || !confirm_password
    ) {
      return res.json({ status: "missing_fields" });
    }

    if (password !== confirm_password)
      return res.json({ status: "password_mismatch" });

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      if (existingUser.is_verified)
        return res.json({ status: "user_exists" });

      const newOtp = generateOTP();
      existingUser.otp = newOtp;
      existingUser.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
      await existingUser.save();
      await sendOTP(email, newOtp);
      return res.json({ status: "otp_resent" });
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

/* ================= VERIFY USER OTP ================= */
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

/* ================= DONATE ================= */
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

/* ================= VERIFY DONATION OTP ================= */
app.post("/verify-donate-otp", async (req, res) => {
  const { donation_id, otp } = req.body;
  const donation = await Donation.findById(donation_id);

  if (!donation) return res.json({ status: "not_found" });
  if (donation.otp !== otp) return res.json({ status: "invalid_otp" });

  donation.is_verified = true;
  donation.otp = null;
  donation.otp_expiry = null;
  await donation.save();

  res.json({ status: "donation_verified" });
});

/* ================= RIDER APIs ================= */
app.post("/rider/pickup", async (req, res) => {
  const donation = await Donation.findById(req.body.donation_id);
  if (!donation) return res.json({ status: "not_found" });

  donation.rider_email = req.body.rider_email;
  donation.donation_status = "picked";
  await donation.save();

  res.json({ status: "pickup_locked" });
});

app.post("/rider/reject-pickup", async (req, res) => {
  const donation = await Donation.findById(req.body.donation_id);
  donation.donation_status = "not_picked";
  donation.rider_email = null;
  donation.rejection_reason = req.body.reason;
  await donation.save();

  res.json({ status: "pickup_rejected" });
});

app.post("/rider/mark-delivered", async (req, res) => {
  const donation = await Donation.findById(req.body.donation_id);
  donation.donation_status = "delivered";
  await donation.save();

  res.json({ status: "delivered_success" });
});

app.post("/rider/my-rides", async (req, res) => {
  const rides = await Donation.find({ rider_email: req.body.rider_email });
  res.json({ status: "success", rides });
});

app.post("/rider/available-pickups", async (req, res) => {
  const donations = await Donation.find({ donation_status: "not_picked" });
  res.json({ status: "success", donations });
});

/* ================= USER PROFILE ================= */
app.post("/get-user-by-email", async (req, res) => {
  const user = await User.findOne({ email: req.body.email }).select("-password");
  res.json({ status: "success", user });
});

app.put("/update-profile", async (req, res) => {
  const user = await User.findOneAndUpdate(
    { email: req.body.email },
    { $set: req.body },
    { new: true }
  );
  res.json({ status: "updated_successfully", user });
});

/* ================= MY REQUESTS ================= */
app.post("/my-requests", async (req, res) => {
  const requests = await Donation.find({ donor_email: req.body.email });
  res.json({ status: "success", requests });
});

/* ================= ADMIN ================= */
app.post("/admin/add-advertisement", async (req, res) => {
  const ad = await Advertisement.create(req.body);
  res.json({ status: "advertisement_added", ad });
});

app.get("/admin/overview", async (req, res) => {
  const totalUsers = await User.countDocuments({ user_type: "user" });
  const totalRiders = await User.countDocuments({ user_type: "rider" });
  const delivered = await Donation.countDocuments({ donation_status: "delivered" });

  res.json({ status: "success", totalUsers, totalRiders, delivered });
});

app.get("/advertisements", async (req, res) => {
  const ads = await Advertisement.find();
  res.json({ status: "success", ads });
});

/* ================= RESEND USER OTP ================= */
app.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ status: "email_required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ status: "not_found" });
    }

    if (user.is_verified) {
      return res.json({ status: "already_verified" });
    }

    const newOtp = generateOTP();
    user.otp = newOtp;
    user.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);

    await user.save();
    await sendOTP(email, newOtp);

    res.json({ status: "otp_resent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});
app.post("/admin/add-job", async (req, res) => {
  const job = await Job.create(req.body);
  res.json({ status: "job_added", job });
});
app.get("/jobs", async (req, res) => {
  const jobs = await Job.find({ is_active: true });
  res.json({ status: "success", jobs });
});
app.post("/apply-job", async (req, res) => {
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

  const job = await Job.findById(job_id);
  if (!job) return res.json({ status: "job_not_found" });

  const application = await JobApplication.create({
    job_id,
    job_title: job.title,
    first_name,
    last_name,
    email,
    phone,
    location,
    resume_link,
    message
  });

  await Notification.create({
    type: "job_application",
    message: `New application for ${job.title}`,
    related_id: application._id
  });

  res.json({ status: "application_submitted" });
});
app.get("/admin/notifications", async (req, res) => {
  const notifications = await Notification.find().sort({ createdAt: -1 });
  res.json({ status: "success", notifications });
});
app.get("/admin/job-applications", async (req, res) => {
  const applications = await JobApplication.find().sort({ createdAt: -1 });
  res.json({ status: "success", applications });
});


const sendInterviewEmail = async ({
  to,
  name,
  role,
  date,
  time,
  mode,
  location
}) => {
  try {
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: {
          name: "DWJD Recruitment",
          email: "naveengit01@gmail.com"
        },
        to: [{ email: to }],
        subject: "Interview Invitation – DWJD",
        htmlContent: `
          <div style="font-family: Arial, sans-serif; line-height:1.6">
            <h2 style="color:#10b981">DWJD – Interview Invitation</h2>

            <p>Dear <strong>${name}</strong>,</p>

            <p>
              Thank you for applying for the position of
              <strong>${role}</strong> at DWJD.
            </p>

            <p>
              We were impressed with your profile and would like to invite you
              for an interview.
            </p>

            <p><strong>Interview Details:</strong></p>
            <ul>
              <li><strong>Date:</strong> ${date}</li>
              <li><strong>Time:</strong> ${time}</li>
              <li><strong>Mode:</strong> ${mode}</li>
              <li><strong>Location / Link:</strong> ${location}</li>
            </ul>

            <p>Please reply to this email to confirm your availability.</p>

            <p>
              Regards,<br />
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

    console.log("✅ Interview email sent");
  } catch (err) {
    console.error("❌ Interview email error:", err.response?.data || err.message);
  }
};

app.post("/admin/send-interview-email", async (req, res) => {
  const {
    email,
    name,
    role,
    date,
    time,
    mode,
    location
  } = req.body;

  if (!email || !name || !role || !date || !time || !mode || !location) {
    return res.json({ status: "missing_fields" });
  }

  await sendInterviewEmail({
    to: email,
    name,
    role,
    date,
    time,
    mode,
    location
  });

  res.json({ status: "interview_email_sent" });
});

/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
