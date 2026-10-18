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
const aiRoutes = require("./routes/ai");
const AdminTodo = require("./models/AdminToDo");
const BecomeRider = require("./models/BecomeRider");
const app = express();

/* ================= MIDDLEWARE ================= */
const allowedOrigins = [
  "https://dwjd.vercel.app",
  "http://localhost:5173",
  "https://admin-org.vercel.app",
  "http://192.168.1.3:5173/",
];

const corsOptions = {
  origin: function (origin, callback) {

    // Allow requests without an origin
    // (Postman, server-to-server requests, etc.)
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));
app.use(express.json());
app.use("/ai", aiRoutes);

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
// ADMIN MODEL
// ===============================

const adminSchema = new mongoose.Schema(
  {
    username: String,
    email: String,
    password: String,
    first_name: String,
    last_name: String,
    phone: String,
    profile_image: String,
    user_type: String,
    is_verified: Boolean,
    is_active: Boolean,
    otp: String,
    otp_expiry: Date
  },
  {
    timestamps: true
  }
);

const Admin = mongoose.model("Admin", adminSchema);
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
  } catch (err) {
  console.error("❌ Signup error:", err);
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
  console.log("DB OTP:", user.otp);
  console.log("Received OTP:", otp);
  console.log("OTP Match:", user.otp === otp);

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
app.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({
        status: "missing_email"
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        status: "not_found"
      });
    }

    if (user.is_verified) {
      return res.json({
        status: "already_verified"
      });
    }

    const otp = generateOTP();

    user.otp = otp;
    user.otp_expiry = new Date(
      Date.now() + 10 * 60 * 1000
    );

    await user.save();

    await sendOTP(email, otp);

    return res.json({
      status: "otp_resent"
    });

  } catch (err) {
    console.error("❌ Resend OTP error:", err);

    return res.status(500).json({
      status: "error"
    });
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


app.post("/admin/todo/create", async (req, res) => {
  try {
    const { tasks } = req.body;

    if (!Array.isArray(tasks) || tasks.length === 0) {
      return res.json({ status: "tasks_required" });
    }

    const today = new Date().toISOString().split("T")[0];

    const exists = await AdminTodo.findOne({ date: today });
    if (exists) {
      return res.json({ status: "already_created_today" });
    }

    await AdminTodo.create({
      date: today,
      tasks: tasks.map(t => ({ title: t }))
    });

    res.json({ status: "todo_created" });

  } catch (err) {
    console.error("Todo create error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.get("/admin/todo/today", async (req, res) => {
  try {
    const today = new Date().toISOString().split("T")[0];

    const todo = await AdminTodo.findOne({ date: today });

    if (!todo) {
      return res.json({ status: "not_created" });
    }

    res.json({
      status: "success",
      todo
    });

  } catch (err) {
    console.error("Fetch todo error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/admin/todo/mark", async (req, res) => {
  try {
    const { task_id } = req.body;

    if (!task_id) {
      return res.json({ status: "task_id_required" });
    }

    const today = new Date().toISOString().split("T")[0];
    const todo = await AdminTodo.findOne({ date: today });

    if (!todo) {
      return res.json({ status: "todo_not_found" });
    }

    const now = Date.now();
    const ONE_HOUR = 60 * 60 * 1000;

    if (todo.lastMarkedAt && now - todo.lastMarkedAt.getTime() < ONE_HOUR) {
      const remaining =
        ONE_HOUR - (now - todo.lastMarkedAt.getTime());

      return res.json({
        status: "wait",
        remainingMinutes: Math.ceil(remaining / 60000)
      });
    }

    const task = todo.tasks.id(task_id);
    if (!task) {
      return res.json({ status: "task_not_found" });
    }

    if (task.completed) {
      return res.json({ status: "already_completed" });
    }

    task.completed = true;
    task.completedAt = new Date();
    todo.lastMarkedAt = new Date();

    await todo.save();

    res.json({ status: "task_marked" });

  } catch (err) {
    console.error("Mark task error:", err);
    res.status(500).json({ status: "error" });
  }
});
app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // ===============================
    // VALIDATION
    // ===============================

    if (!username || !password) {
      return res.json({
        status: "missing_fields",
        message: "Username and password are required"
      });
    }

    // ===============================
    // FIND ADMIN
    // ===============================

    const admin = await Admin.findOne({
      username: username
    });

    if (!admin) {
      return res.json({
        status: "invalid_credentials",
        message: "Invalid username or password"
      });
    }

    // ===============================
    // CHECK PASSWORD
    // ===============================

    const passwordMatch = await bcrypt.compare(
      password,
      admin.password
    );

    if (!passwordMatch) {
      return res.json({
        status: "invalid_credentials",
        message: "Invalid username or password"
      });
    }

    // ===============================
    // CHECK ACCOUNT STATUS
    // ===============================

    if (!admin.is_active) {
      return res.json({
        status: "account_inactive",
        message: "Admin account is inactive"
      });
    }

    // ===============================
    // CHECK EMAIL VERIFICATION
    // ===============================

    if (!admin.is_verified) {

      return res.json({
        status: "otp_required",
        email: admin.email
      });
    }

    // ===============================
    // CREATE ADMIN JWT
    // ===============================

    const token = jwt.sign(
      {
        id: admin._id,
        role: admin.user_type,
        admin: true
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    // ===============================
    // LOGIN SUCCESS
    // ===============================

    return res.json({
      status: "login_success",
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        first_name: admin.first_name,
        last_name: admin.last_name,
        phone: admin.phone,
        profile_image: admin.profile_image,
        user_type: admin.user_type,
        is_verified: admin.is_verified,
        is_active: admin.is_active
      }
    });

  } catch (error) {

    console.error("Admin login error:", error);

    return res.status(500).json({
      status: "error",
      message: "Server error"
    });
  }
});

app.post("/admin/create-rider", async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      first_name,
      last_name,
      phone,
      profile_image
    } = req.body;

    if (
      !username ||
      !email ||
      !password ||
      !first_name ||
      !last_name ||
      !phone
    ) {
      return res.json({
        status: "missing_fields"
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.json({
        status: "user_exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const rider = await User.create({
      username,
      email,
      password: hashedPassword,
      first_name,
      last_name,
      phone,
      profile_image: profile_image || "",
      user_type: "rider",

      is_rider_approved: false,
      is_verified: false,
      is_active: true,

      otp: null,
      otp_expiry: null
    });

    console.log("✅ Rider created:", rider.email);

    return res.json({
      status: "rider_created",
      rider: {
        id: rider._id,
        username: rider.username,
        email: rider.email,
        first_name: rider.first_name,
        last_name: rider.last_name,
        user_type: rider.user_type,
        is_verified: rider.is_verified,
        is_rider_approved: rider.is_rider_approved,
        is_active: rider.is_active
      }
    });

  } catch (err) {
    console.error("❌ Create rider error:", err);

    return res.status(500).json({
      status: "error"
    });
  }
});
// ==========================================
// BECOME RIDER: VERIFY EMAIL ELIGIBILITY
// ==========================================

app.post("/rider/verify-email", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || typeof email !== "string") {
      return res.status(400).json({
        status: "missing_email",
        message: "Please enter your email address.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        status: "invalid_email",
        message: "Please enter a valid email address.",
      });
    }

    // Check whether this email already belongs to a rider
    const existingRider = await User.findOne({
      email: normalizedEmail,
      user_type: "rider",
    });

    if (existingRider) {
      return res.status(409).json({
        status: "rider_already_exists",
        message: "A rider account already exists for this email address.",
      });
    }

    // Check for an existing request
    const existingRequest = await BecomeRider.findOne({
      email: normalizedEmail,
      status: {
        $in: ["pending", "under_review", "approved"],
      },
    });

    if (existingRequest) {
      return res.status(409).json({
        status: "request_already_exists",
        message:
          "A rider account request already exists for this email address.",
      });
    }

    return res.status(200).json({
      status: "email_eligible",
      message: "You can continue with your rider account request.",
    });
  } catch (error) {
    console.error("Rider email verification error:", error);

    return res.status(500).json({
      status: "error",
      message: "Unable to verify your email right now.",
    });
  }
});
// ==========================================
// BECOME RIDER: SUBMIT ACCOUNT REQUEST
// ==========================================

app.post("/rider/request-account", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      phone,
    } = req.body;

    // ======================================
    // 1. VALIDATE REQUIRED FIELDS
    // ======================================

    if (
      !first_name?.trim() ||
      !last_name?.trim() ||
      !email?.trim() ||
      !phone?.trim()
    ) {
      return res.status(400).json({
        status: "missing_fields",
        message: "Please fill in all required fields.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const normalizedFirstName = first_name.trim();
    const normalizedLastName = last_name.trim();
    const normalizedPhone = phone.trim();

    // ======================================
    // 2. VALIDATE EMAIL
    // ======================================

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        status: "invalid_email",
        message: "Please enter a valid email address.",
      });
    }

    // ======================================
    // 3. VALIDATE MOBILE NUMBER
    // ======================================

    // Accept international formats such as +919876543210.
    const normalizedPhoneDigits = normalizedPhone.replace(/[\s()-]/g, "");

    if (!/^\+?\d{10,15}$/.test(normalizedPhoneDigits)) {
      return res.status(400).json({
        status: "invalid_phone",
        message: "Please enter a valid mobile number.",
      });
    }

    // ======================================
    // 4. CHECK EXISTING RIDER ACCOUNT
    // ======================================

    const existingRider = await User.findOne({
      email: normalizedEmail,
      user_type: "rider",
    });

    if (existingRider) {
      return res.status(409).json({
        status: "rider_already_exists",
        message:
          "A rider account already exists for this email address.",
      });
    }

    // ======================================
    // 5. CHECK EXISTING REQUEST
    // ======================================

    const existingRequest = await BecomeRider.findOne({
      email: normalizedEmail,
      status: {
        $in: ["pending", "under_review", "approved"],
      },
    });

    if (existingRequest) {
      return res.status(409).json({
        status: "request_already_exists",
        message:
          "Your rider account request has already been submitted.",
      });
    }

    // ======================================
    // 6. SAVE REQUEST TO MONGODB
    // ======================================

    const riderRequest = await BecomeRider.create({
      first_name: normalizedFirstName,
      last_name: normalizedLastName,
      email: normalizedEmail,
      phone: normalizedPhoneDigits,

      email_checked: true,

      status: "pending",

      reviewed_by: null,
      reviewed_at: null,

      rejection_reason: "",

      created_user_id: null,
      account_created_at: null,
    });

    console.log(
      "New rider request received:",
      riderRequest._id
    );

    // ======================================
    // 7. SEND CONFIRMATION EMAIL
    // ======================================

    let emailSent = false;

    try {
      await sendEmail({
        to: normalizedEmail,

        subject:
          "Your DWJD Rider Account Request Has Been Received",

        html: `
          <!DOCTYPE html>
          <html>
            <body style="
              margin: 0;
              padding: 0;
              background-color: #f4f6f8;
              font-family: Arial, sans-serif;
            ">
              <div style="
                max-width: 600px;
                margin: 30px auto;
                background: #ffffff;
                border-radius: 12px;
                overflow: hidden;
                border: 1px solid #e5e7eb;
              ">
                <div style="
                  background: #111827;
                  color: #ffffff;
                  padding: 28px;
                  text-align: center;
                ">
                  <h1 style="margin: 0;">
                    DWJD
                  </h1>

                  <p style="margin-bottom: 0;">
                    Rider Account Request
                  </p>
                </div>

                <div style="padding: 30px;">
                  <h2 style="color: #111827;">
                    Hi ${escapeHtml(normalizedFirstName)},
                  </h2>

                  <p style="
                    color: #4b5563;
                    line-height: 1.7;
                  ">
                    Thank you for your interest in becoming
                    a rider with DWJD!
                  </p>

                  <p style="
                    color: #4b5563;
                    line-height: 1.7;
                  ">
                    We have successfully received your
                    rider account request.
                  </p>

                  <div style="
                    background: #eff6ff;
                    border-left: 4px solid #2563eb;
                    padding: 16px;
                    margin: 24px 0;
                    border-radius: 6px;
                  ">
                    <h3 style="
                      margin-top: 0;
                      color: #1d4ed8;
                    ">
                      What happens next?
                    </h3>

                    <p style="
                      color: #374151;
                      line-height: 1.7;
                      margin-bottom: 0;
                    ">
                      Our Customer Support team will review
                      your request within 24 hours. We will
                      contact you by email regarding the
                      next steps.
                    </p>
                  </div>

                  <p style="
                    color: #4b5563;
                    line-height: 1.7;
                  ">
                    Please keep an eye on your inbox for
                    further updates.
                  </p>

                  <p style="
                    color: #4b5563;
                    line-height: 1.7;
                  ">
                    Thank you for your patience.
                  </p>

                  <p style="
                    color: #111827;
                    line-height: 1.7;
                  ">
                    Best regards,<br />
                    <strong>DWJD Customer Support Team</strong>
                  </p>
                </div>

                <div style="
                  background: #f9fafb;
                  padding: 16px;
                  text-align: center;
                  color: #6b7280;
                  font-size: 12px;
                ">
                  This is an automated confirmation email
                  from DWJD.
                </div>
              </div>
            </body>
          </html>
        `,
      });

      emailSent = true;
    } catch (emailError) {
      // Keep the saved request even if the email fails.
      console.error(
        "Rider request confirmation email failed:",
        emailError.message
      );
    }

    // ======================================
    // 8. RETURN SUCCESS RESPONSE
    // ======================================

    return res.status(201).json({
      status: "request_submitted",

      message:
        "Your rider account request has been submitted successfully. Our Customer Support team will review your request within 24 hours.",

      request_id: riderRequest._id,

      email_sent: emailSent,
    });
  } catch (error) {
    console.error("Become Rider request error:", error);

    return res.status(500).json({
      status: "error",
      message:
        "We could not submit your request right now. Please try again later.",
    });
  }
});


// ==========================================
// HTML ESCAPING HELPER
// ==========================================

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, (character) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };

    return entities[character];
  });
}
/* ================= START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
