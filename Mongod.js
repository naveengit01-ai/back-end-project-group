require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const crypto = require("crypto");
// Models
const User = require("./models/User");
const Donation = require("./models/Donation");
const Advertisement = require("./models/Advertisement");
const BecomeRider = require("./models/BecomeRider");
const Admin = require("./models/Admin");

const aiRoutes = require("./routes/ai");
const app = express();

/* ================= MIDDLEWARE ================= */
const allowedOrigins = [
  "https://dwjd.vercel.app",
  "http://localhost:5173",
  "https://admin-org.vercel.app",
  "http://192.168.1.3:5173",
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests without an origin (Postman, server-to-server, etc.)
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
  .catch((err) => {
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
      htmlContent: html,
    },
    {
      headers: {
        "api-key": process.env.BREVO_API_KEY,
        "Content-Type": "application/json",
      },
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
    `,
  });
};

/* =================================================
   AUTH (USER & RIDER)
================================================= */

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
      longitude,
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
    )
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
      is_verified: false,
    };

    if (user_type === "rider") {
      userData.rider_location = {
        lat: Number(latitude),
        lng: Number(longitude),
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
  try {
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
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ status: "error" });
  }
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
        email: user.email,
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
      user,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ status: "missing_email" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ status: "not_found" });
    }

    if (user.is_verified) {
      return res.json({ status: "already_verified" });
    }

    const otp = generateOTP();

    user.otp = otp;
    user.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);

    await user.save();
    await sendOTP(email, otp);

    return res.json({ status: "otp_resent" });
  } catch (err) {
    console.error("❌ Resend OTP error:", err);
    return res.status(500).json({ status: "error" });
  }
});

/* =================================================
   USER PROFILE
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

    if (first_name !== undefined) user.first_name = first_name;
    if (last_name !== undefined) user.last_name = last_name;
    if (phone !== undefined) user.phone = phone;

    await user.save();

    const safeUser = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      phone: user.phone,
      user_type: user.user_type,
      is_verified: user.is_verified,
    };

    res.json({
      status: "updated_successfully",
      user: safeUser,
    });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ status: "error" });
  }
});

/* =================================================
   DONATIONS & RIDER PICKUPS
================================================= */

app.post("/donate", async (req, res) => {
  try {
    const otp = generateOTP();
    const donation = await Donation.create({
      ...req.body,
      otp,
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
    });

    await sendOTP(req.body.donor_email, otp);
    res.json({ status: "otp_sent", donation_id: donation._id });
  } catch (err) {
    console.error("Donate error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/verify-donate-otp", async (req, res) => {
  try {
    const { donation_id, otp, rider_email } = req.body;

    const donation = await Donation.findById(donation_id);
    if (!donation) return res.json({ status: "not_found" });

    if (donation.otp !== otp) {
      return res.json({ status: "invalid_otp" });
    }

    donation.is_verified = true;
    donation.otp = null;
    donation.otp_expiry = null;

    if (rider_email) {
      donation.rider_email = rider_email;
      donation.donation_status = "picked";
    }

    await donation.save();

    res.json({
      status: rider_email ? "donation_verified_and_picked" : "donation_verified",
    });
  } catch (err) {
    console.error("Verify donate OTP error:", err);
    res.status(500).json({ status: "error" });
  }
});

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

    const otp = generateOTP();

    donation.otp = otp;
    donation.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
    await donation.save();

    await sendOTP(donation.donor_email, otp);

    res.json({ status: "otp_resent" });
  } catch (err) {
    console.error("Resend OTP error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/my-requests", async (req, res) => {
  try {
    const requests = await Donation.find({ donor_email: req.body.email });
    res.json({ status: "success", requests });
  } catch (err) {
    console.error("My requests error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/rider/available-pickups", async (req, res) => {
  try {
    const donations = await Donation.find({ donation_status: "not_picked" });
    res.json({ status: "success", donations });
  } catch (err) {
    console.error("Available pickups error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/rider/pickup", async (req, res) => {
  try {
    const donation = await Donation.findById(req.body.donation_id);
    if (!donation) return res.json({ status: "not_found" });

    donation.rider_email = req.body.rider_email;
    donation.donation_status = "picked";
    await donation.save();

    res.json({ status: "pickup_locked" });
  } catch (err) {
    console.error("Pickup error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/rider/mark-delivered", async (req, res) => {
  try {
    const donation = await Donation.findById(req.body.donation_id);
    if (!donation) return res.json({ status: "not_found" });

    donation.donation_status = "delivered";
    await donation.save();

    res.json({ status: "delivered_success" });
  } catch (err) {
    console.error("Mark delivered error:", err);
    res.status(500).json({ status: "error" });
  }
});

app.post("/rider/my-rides", async (req, res) => {
  try {
    const { rider_email } = req.body;

    if (!rider_email) {
      return res.json({ status: "missing_fields" });
    }

    const rides = await Donation.find({ rider_email }).sort({ createdAt: -1 });

    res.json({
      status: "success",
      rides,
    });
  } catch (err) {
    console.error("My rides error:", err);
    res.status(500).json({ status: "error" });
  }
});

/* =================================================
   ADVERTISEMENTS
================================================= */

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
   ADMIN AUTH & MANAGEMENT
================================================= */

app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.json({
        status: "missing_fields",
        message: "Username and password are required",
      });
    }

    const admin = await Admin.findOne({ username });

    if (!admin) {
      return res.json({
        status: "invalid_credentials",
        message: "Invalid username or password",
      });
    }

    const passwordMatch = await bcrypt.compare(password, admin.password);

    if (!passwordMatch) {
      return res.json({
        status: "invalid_credentials",
        message: "Invalid username or password",
      });
    }

    if (!admin.is_active) {
      return res.json({
        status: "account_inactive",
        message: "Admin account is inactive",
      });
    }

    if (!admin.is_verified) {
      return res.json({
        status: "otp_required",
        email: admin.email,
      });
    }

    const token = jwt.sign(
      {
        id: admin._id,
        role: admin.user_type,
        admin: true,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

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
        is_active: admin.is_active,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);
    return res.status(500).json({
      status: "error",
      message: "Server error",
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
      profile_image,
    } = req.body;

    if (!username || !email || !password || !first_name || !last_name || !phone) {
      return res.json({ status: "missing_fields" });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.json({ status: "user_exists" });
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
      otp_expiry: null,
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
        is_active: rider.is_active,
      },
    });
  } catch (err) {
    console.error("❌ Create rider error:", err);
    return res.status(500).json({ status: "error" });
  }
});

/* =================================================
   BECOME RIDER ONBOARDING FLOW
================================================= */

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
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        status: "invalid_email",
        message: "Please enter a valid email address.",
      });
    }

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

    const existingRequest = await BecomeRider.findOne({
      email: normalizedEmail,
      status: {
        $in: ["pending", "under_review", "approved"],
      },
    });

    if (existingRequest) {
      return res.status(409).json({
        status: "request_already_exists",
        message: "A rider account request already exists for this email address.",
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

app.post("/rider/request-account", async (req, res) => {
  try {
    const { first_name, last_name, email, phone } = req.body;

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

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        status: "invalid_email",
        message: "Please enter a valid email address.",
      });
    }

    const normalizedPhoneDigits = normalizedPhone.replace(/[\s()-]/g, "");
    if (!/^\+?\d{10,15}$/.test(normalizedPhoneDigits)) {
      return res.status(400).json({
        status: "invalid_phone",
        message: "Please enter a valid mobile number.",
      });
    }

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

    const existingRequest = await BecomeRider.findOne({
      email: normalizedEmail,
      status: {
        $in: ["pending", "under_review", "approved"],
      },
    });

    if (existingRequest) {
      return res.status(409).json({
        status: "request_already_exists",
        message: "Your rider account request has already been submitted.",
      });
    }

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

    console.log("New rider request received:", riderRequest._id);

    let emailSent = false;

    try {
      await sendEmail({
        to: normalizedEmail,
        subject: "Your DWJD Rider Account Request Has Been Received",
        html: `
          <!DOCTYPE html>
          <html>
            <body style="margin: 0; padding: 0; background-color: #f4f6f8; font-family: Arial, sans-serif;">
              <div style="max-width: 600px; margin: 30px auto; background: #ffffff; border-radius: 12px; overflow: hidden; border: 1px solid #e5e7eb;">
                <div style="background: #111827; color: #ffffff; padding: 28px; text-align: center;">
                  <h1 style="margin: 0;">DWJD</h1>
                  <p style="margin-bottom: 0;">Rider Account Request</p>
                </div>
                <div style="padding: 30px;">
                  <h2 style="color: #111827;">Hi ${escapeHtml(normalizedFirstName)},</h2>
                  <p style="color: #4b5563; line-height: 1.7;">
                    Thank you for your interest in becoming a rider with DWJD!
                  </p>
                  <p style="color: #4b5563; line-height: 1.7;">
                    We have successfully received your rider account request.
                  </p>
                  <div style="background: #eff6ff; border-left: 4px solid #2563eb; padding: 16px; margin: 24px 0; border-radius: 6px;">
                    <h3 style="margin-top: 0; color: #1d4ed8;">What happens next?</h3>
                    <p style="color: #374151; line-height: 1.7; margin-bottom: 0;">
                      Our Customer Support team will review your request within 24 hours. We will contact you by email regarding the next steps.
                    </p>
                  </div>
                  <p style="color: #4b5563; line-height: 1.7;">Please keep an eye on your inbox for further updates.</p>
                  <p style="color: #4b5563; line-height: 1.7;">Thank you for your patience.</p>
                  <p style="color: #111827; line-height: 1.7;">
                    Best regards,<br />
                    <strong>DWJD Customer Support Team</strong>
                  </p>
                </div>
                <div style="background: #f9fafb; padding: 16px; text-align: center; color: #6b7280; font-size: 12px;">
                  This is an automated confirmation email from DWJD.
                </div>
              </div>
            </body>
          </html>
        `,
      });
      emailSent = true;
    } catch (emailError) {
      console.error(
        "Rider request confirmation email failed:",
        emailError.message
      );
    }

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
      message: "We could not submit your request right now. Please try again later.",
    });
  }
});

/* =================================================
   HTML ESCAPING HELPER
================================================= */

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
/* =================================================
   CREATE ADMIN ACCOUNT API
================================================= */

app.post("/admin/create-admin", async (req, res) => {
  try {
    const {
      username,
      email,
      first_name,
      last_name,
      phone,
      roles,
    } = req.body;

    // 1. Validate required fields
    if (
      !username?.trim() ||
      !email?.trim() ||
      !first_name?.trim() ||
      !last_name?.trim() ||
      !phone?.trim() ||
      !Array.isArray(roles) ||
      roles.length === 0
    ) {
      return res.status(400).json({
        status: "missing_fields",
        message: "Please provide all required fields and at least one role.",
      });
    }

    // 2. Normalize input
    const normalizedUsername = username.trim();
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim();

    // 3. Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        status: "invalid_email",
        message: "Please enter a valid email address.",
      });
    }

    // 4. Validate roles
    const allowedRoles = [
      "gm",
      "customersupport",
      "marketing",
      "finance",
      "operations",
      "hr",
      "admin",
    ];

    const uniqueRoles = [...new Set(roles)];

    if (
      uniqueRoles.length !== roles.length ||
      uniqueRoles.some((role) => !allowedRoles.includes(role))
    ) {
      return res.status(400).json({
        status: "invalid_roles",
        message: "One or more selected roles are invalid.",
      });
    }

    // 5. Check duplicate username, email, or phone
    const existingAdmin = await Admin.findOne({
      $or: [
        { username: normalizedUsername },
        { email: normalizedEmail },
        { phone: normalizedPhone },
      ],
    });

    if (existingAdmin) {
      let message = "An admin account already exists.";

      if (existingAdmin.username === normalizedUsername) {
        message = "Username already exists.";
      } else if (existingAdmin.email === normalizedEmail) {
        message = "Email already exists.";
      } else if (existingAdmin.phone === normalizedPhone) {
        message = "Phone number already exists.";
      }

      return res.status(409).json({
        status: "admin_exists",
        message,
      });
    }

    // 6. Generate a temporary password
    const temporaryPassword = crypto.randomBytes(12).toString("base64url");

    // 7. Hash the password before storing it
    const hashedPassword = await bcrypt.hash(temporaryPassword, 12);

    // 8. Create admin account
    const newAdmin = await Admin.create({
      username: normalizedUsername,
      email: normalizedEmail,
      first_name: first_name.trim(),
      last_name: last_name.trim(),
      phone: normalizedPhone,
      password: hashedPassword,
      user_type: "admin",
      roles: uniqueRoles,
      profile_image: "",
      is_verified: true,
      is_active: true,
    });

    // 9. Send credentials using your existing Brevo email function
    try {
      await sendEmail({
        to: normalizedEmail,
        subject: "Your DWJD Admin Account Credentials",
        html: `
          <!DOCTYPE html>
          <html>
          <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Welcome to DWJD Admin</h2>

            <p>Hello ${escapeHtml(first_name.trim())},</p>

            <p>Your admin account has been created successfully.</p>

            <p><strong>Username:</strong>
              ${escapeHtml(normalizedUsername)}
            </p>

            <p><strong>Temporary Password:</strong>
              ${escapeHtml(temporaryPassword)}
            </p>

            <p><strong>Assigned Roles:</strong>
              ${uniqueRoles.map(escapeHtml).join(", ")}
            </p>

            <p>Please log in and change your temporary password.</p>

            <p>Regards,<br />DWJD Team</p>
          </body>
          </html>
        `,
      });

      return res.status(201).json({
        status: "admin_created",
        message: "Admin account created and credentials sent successfully.",
        email_sent: true,
        admin: {
          id: newAdmin._id,
          username: newAdmin.username,
          email: newAdmin.email,
          first_name: newAdmin.first_name,
          last_name: newAdmin.last_name,
          roles: newAdmin.roles,
        },
      });
    } catch (emailError) {
      console.error("Admin credentials email failed:", emailError.message);

      return res.status(201).json({
        status: "admin_created_email_failed",
        message:
          "Admin account was created, but the credentials email could not be sent. Arrange a secure password reset before allowing login.",
        email_sent: false,
        admin: {
          id: newAdmin._id,
          username: newAdmin.username,
          email: newAdmin.email,
        },
      });
    }
  } catch (error) {
    console.error("Create admin error:", error);

    if (error.code === 11000) {
      return res.status(409).json({
        status: "admin_exists",
        message: "Username, email, or phone number already exists.",
      });
    }

    return res.status(500).json({
      status: "error",
      message: "Unable to create admin account.",
    });
  }
});

/* ================= SERVER START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));