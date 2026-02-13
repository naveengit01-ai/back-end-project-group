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
const YoutubeContent = require("./models/YoutubeContent");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(cors());
app.options("*", cors());


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
  try {
    const { email, password, user_type } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ status: "invalid_credentials" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.json({ status: "invalid_credentials" });
    }

    /* 🔴 NOT VERIFIED → OTP REQUIRED */
    if (!user.is_verified) {
      return res.json({
        status: "otp_required",
        email: user.email
      });
    }

    /* 🔐 ROLE CHECK (NON-ADMIN ONLY) */
    if (user.user_type !== "admin" && user.user_type !== user_type) {
      return res.json({ status: "invalid_credentials" });
    }

    /* ✅ LOGIN SUCCESS */
    const token = jwt.sign(
      { id: user._id, role: user.user_type },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      status: "login_success",
      token,
      user
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ status: "error" });
  }
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

app.post("/admin/add-advertisement", async (req, res) => {
  try {
    const ad = await Advertisement.create(req.body);
    res.json({ status: "advertisement_added", ad });
  } catch (err) {
    console.error("Add advertisement error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.get("/advertisements", async (req, res) => {
  try {
    const ads = await Advertisement.find().sort({ createdAt: -1 });
    res.json({ status: "success", ads });
  } catch (err) {
    console.error("Fetch ads error:", err);
    res.status(500).json({ status: "error" });
  }
});

/* =================================================
   RIDER → MY RIDES (USED BY MyRides.jsx)
================================================= */

app.post("/rider/my-rides", async (req, res) => {
  try {
    const { rider_email } = req.body;

    if (!rider_email) {
      return res.json({ status: "missing_fields" });
    }

    const rides = await Donation.find({
      rider_email
    }).sort({ createdAt: -1 });

    res.json({
      status: "success",
      rides
    });
  } catch (err) {
    console.error("My rides error:", err);
    res.status(500).json({ status: "error" });
  }
});

/* =================================================
   RESEND DONATION OTP
================================================= */

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

    // Generate new OTP
    const otp = generateOTP();

    donation.otp = otp;
    donation.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
    await donation.save();

    // Send OTP again
    await sendOTP(donation.donor_email, otp);

    res.json({ status: "otp_resent" });
  } catch (err) {
    console.error("Resend OTP error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/verify-donate-otp", async (req, res) => {
  const { donation_id, otp, rider_email } = req.body;

  const donation = await Donation.findById(donation_id);
  if (!donation) return res.json({ status: "not_found" });

  if (donation.otp !== otp) {
    return res.json({ status: "invalid_otp" });
  }

  donation.is_verified = true;
  donation.otp = null;
  donation.otp_expiry = null;

  // lock pickup
  if (rider_email) {
    donation.rider_email = rider_email;
    donation.donation_status = "picked";
  }

  await donation.save();

  res.json({ status: "donation_verified_and_picked" });
});

/* =================================================
   GET USER BY EMAIL (PROFILE)
================================================= */

app.post("/get-user-by-email", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ status: "missing_fields" });
    }

    const user = await User.findOne({ email }).select("-password -otp -otp_expiry");
    if (!user) {
      return res.json({ status: "not_found" });
    }

    res.json({ status: "success", user });
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ status: "error" });
  }
});

/* =================================================
   UPDATE PROFILE
================================================= */

app.put("/update-profile", async (req, res) => {
  try {
    const { email, first_name, last_name, phone } = req.body;

    if (!email) {
      return res.json({ status: "missing_email" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ status: "not_found" });
    }

    // ✅ Update only allowed fields
    if (first_name !== undefined) user.first_name = first_name;
    if (last_name !== undefined) user.last_name = last_name;
    if (phone !== undefined) user.phone = phone;

    await user.save();

    // ❌ never send password / otp back
    const safeUser = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      phone: user.phone,
      user_type: user.user_type,
      is_verified: user.is_verified
    };

    res.json({
      status: "updated_successfully",
      user: safeUser
    });

  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ status: "error" });
  }
});

//  Aplication details //

app.get("/admin/application/:id", async (req, res) => {
  const application = await JobApplication.findById(req.params.id);
  if (!application) return res.json({ status: "not_found" });

  res.json({ status: "success", application });
});

// not selected one 

app.post("/admin/interview/not-selected", async (req, res) => {
  const appData = await JobApplication.findById(req.body.application_id);
  if (!appData) return res.json({ status: "not_found" });

  appData.status = "rejected";
  await appData.save();

  await sendEmail({
    to: appData.email,
    subject: "Application Update – DWJD",
    html: `
      <p>Hi ${appData.first_name},</p>
      <p>Thank you for applying. Unfortunately, you were not selected.</p>
      <p>You can explore new opportunities here:</p>
      <a href="https://dwjd.vercel.app/career">Career Page</a>
      <p>Best wishes,<br/>DWJD Team</p>
    `
  });

  res.json({ status: "rejection_email_sent" });
});

// create employe 

app.post("/admin/create-employee", async (req, res) => {
  try {
    const { application_id, username, password } = req.body;

    if (!application_id || !username || !password) {
      return res.json({ status: "missing_fields" });
    }

    /* 🔍 FETCH APPLICATION */
    const application = await JobApplication.findById(application_id);
    if (!application) {
      return res.json({ status: "application_not_found" });
    }

    /* 🎯 ROLE = JOB APPLIED */
    const user_type = application.job_title.toLowerCase();

    const hashedPassword = await bcrypt.hash(password, 10);

    /* 🔍 CHECK IF USER EXISTS */
    let user = await User.findOne({ email: application.email });

    if (user) {
      /* ✅ UPDATE EXISTING USER */
      user.username = username;
      user.user_type = user_type;
      user.password = hashedPassword;
      user.is_verified = true; // direct access
      await user.save();
    } else {
      /* ✅ CREATE NEW USER */
      await User.create({
        username,
        first_name: application.first_name,
        last_name: application.last_name,
        email: application.email,
        phone: application.phone,
        user_type,
        password: hashedPassword,
        is_verified: true
      });
    }

    /* ✅ MARK APPLICATION AS SELECTED */
    application.status = "selected";
    await application.save();

    /* 📩 SEND SELECTION + PASSWORD EMAIL */
    try {
      await sendEmail({
        to: application.email,
        subject: "🎉 Congratulations! You Are Selected – DWJD",
        html: `
          <h2>Congratulations ${application.first_name}! 🎉</h2>

          <p>
            You have been <b style="color:green;">SELECTED</b> for the role of
            <b>${application.job_title}</b> at <b>DWJD</b>.
          </p>

          <hr/>

          <h3>🔐 Login Credentials</h3>
          <p>
            <b>Email:</b> ${application.email}<br/>
            <b>Password:</b>
            <span style="font-size:18px;font-weight:bold;">
              ${password}
            </span>
          </p>

          <p>Please login and change your password after first login.</p>

          <hr/>

          <p>
            If you face any issues, contact us at<br/>
            📧 <b>support@dwjd.org</b>
          </p>

          <p>Welcome to the team 🚀</p>
          <p><b>DWJD Team</b></p>
        `
      });
    } catch (mailErr) {
      console.error("❌ Selection email failed:", mailErr.message);
      return res.json({ status: "employee_created_but_mail_failed" });
    }

    res.json({ status: "employee_created_and_mail_sent" });

  } catch (err) {
    console.error("Create employee error:", err);
    res.status(500).json({ status: "error" });
  }
});


// Get application by ID

app.get("/admin/application/:id", async (req, res) => {
  try {
    const application = await JobApplication.findById(req.params.id);

    if (!application) {
      return res.json({ status: "not_found" });
    }

    res.json({ status: "success", application });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/admin/youtube-content", async (req, res) => {
  try {
    const { title, embedCode, mainTopics } = req.body;

    // ✅ Validation
    if (!title) {
      return res.json({ status: "title_required" });
    }

    if (!Array.isArray(mainTopics) || mainTopics.length === 0) {
      return res.json({ status: "main_topics_required" });
    }

    await YoutubeContent.create({
      title,
      embedCode: embedCode || "",
      mainTopics
    });

    res.json({ status: "content_added" });
  } catch (err) {
    console.error("Add content error:", err);
    res.status(500).json({ status: "error" });
  }
});



app.get("/youtube-content", async (req, res) => {
  try {
    const contents = await YoutubeContent.find({ is_active: true })
      .select("title views createdAt")
      .sort({ createdAt: -1 });

    res.json({
      status: "success",
      contents
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});


app.get("/youtube/:id", async (req, res) => {
  try {
    const content = await YoutubeContent.findOne({
      _id: req.params.id,
      is_active: true
    });

    if (!content) {
      return res.json({ status: "not_found" });
    }

    // 👀 Increment views
    content.views += 1;
    await content.save();

    res.json({
      status: "success",
      content
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});


/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
