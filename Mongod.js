require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const crypto = require("crypto");

const multer = require("multer");
const { google } = require("googleapis");
const { Readable } = require("stream");
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
  "https://dwjd-org.vercel.app",
  "http://192.168.1.3:5173",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      console.error("Blocked CORS origin:", origin);
      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Accept"],
    credentials: true,
  })
);
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
// ============================================
// ADMIN REPORT AUTHENTICATION
// ============================================

const requireGMForReports = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;

    if (
      !authorization ||
      !authorization.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Please log in as an administrator.",
      });
    }

    const token = authorization.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Authentication token is missing.",
      });
    }

    // Verify the token using the same secret as admin login.
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (!decoded.id || decoded.admin !== true) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Invalid administrator session.",
      });
    }

    // Fetch the current admin record from MongoDB.
    // Do not rely exclusively on the role stored in the JWT.
    const admin = await Admin.findById(decoded.id)
      .select("-password -otp -otp_expiry")
      .lean();

    if (!admin) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Administrator account not found.",
      });
    }

    if (!admin.is_active) {
      return res.status(403).json({
        status: "forbidden",
        message: "Your administrator account is inactive.",
      });
    }

    // Check the current database role and assigned roles.
    const assignedRoles = Array.isArray(admin.roles)
      ? admin.roles.map((role) =>
          String(role).toLowerCase()
        )
      : [];

    const isGM =
      String(admin.user_type || "").toLowerCase() === "gm" ||
      assignedRoles.includes("gm");

    if (!isGM) {
      return res.status(403).json({
        status: "forbidden",
        message:
          "Only the General Manager can access organization reports.",
      });
    }

    req.reportAdmin = {
      id: String(admin._id),
      username: admin.username,
      roles: assignedRoles,
    };

    return next();
  } catch (error) {
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError" ||
      error.name === "NotBeforeError"
    ) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Your session is invalid or has expired.",
      });
    }

    console.error("GM reports authentication error:", error);

    return res.status(500).json({
      status: "error",
      message: "Unable to verify administrator access.",
    });
  }
};
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

/* =========================================
   SIGNUP API
   Google Drive + MongoDB + Email OTP
========================================= */

app.post(
  "/signup",

  (req, res, next) => {
    profileUpload.single("profile_image")(
      req,
      res,
      (error) => {
        if (!error) {
          return next();
        }

        if (error instanceof multer.MulterError) {
          if (error.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
              status: "file_too_large",
              message: "Profile image cannot exceed 5 MB.",
            });
          }

          return res.status(400).json({
            status: "upload_error",
            message: error.message,
          });
        }

        return res.status(400).json({
          status: "invalid_image",
          message: error.message,
        });
      }
    );
  },

  async (req, res) => {
    let uploadedDriveFileId = null;
    let createdUserId = null;

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

      /* 1. Validate required fields */

      if (
        !username?.trim() ||
        !first_name?.trim() ||
        !last_name?.trim() ||
        !phone?.trim() ||
        !email?.trim() ||
        !user_type ||
        !password ||
        !confirm_password
      ) {
        return res.status(400).json({
          status: "missing_fields",
          message: "Please complete all required fields.",
        });
      }

      /* 2. Restrict public signup account types */

      if (!["user", "rider"].includes(user_type)) {
        return res.status(400).json({
          status: "invalid_user_type",
        });
      }

      /* 3. Validate username */

      if (username.trim().length < 6) {
        return res.status(400).json({
          status: "invalid_username",
          message: "Username must be at least 6 characters.",
        });
      }

      /* 4. Validate password */

      if (password !== confirm_password) {
        return res.status(400).json({
          status: "password_mismatch",
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          status: "weak_password",
          message: "Password must be at least 8 characters.",
        });
      }

      /* 5. Normalize email */

      const normalizedEmail = email.trim().toLowerCase();

      /* 6. Check existing account */

      const existingUser = await User.findOne({
        email: normalizedEmail,
      });

      if (existingUser) {
        if (existingUser.is_verified) {
          return res.status(409).json({
            status: "user_exists",
          });
        }

        /*
          Preserve the existing OTP resend behavior.
          Don't upload another image for an existing account.
        */

        const otp = generateOTP();

        existingUser.otp = otp;

        existingUser.otp_expiry = new Date(
          Date.now() + 10 * 60 * 1000
        );

        await existingUser.save();

        await sendOTP(normalizedEmail, otp);

        return res.json({
          status: "otp_resent",
        });
      }

      /* 7. Upload optional profile image */

      let profileImageUrl = "";

      if (req.file) {
        const uploadedImage = await uploadProfileImage(
          req.file,
          user_type
        );

        uploadedDriveFileId = uploadedImage.fileId;
        profileImageUrl = uploadedImage.url;
      }

      /* 8. Hash password */

      const hashedPassword = await bcrypt.hash(
        password,
        10
      );

      /* 9. Generate OTP */

      const otp = generateOTP();

      /* 10. Prepare MongoDB document */

      const userData = {
        username: username.trim(),
        first_name: first_name.trim(),
        last_name: last_name.trim(),
        phone: phone.trim(),
        email: normalizedEmail,
        user_type,

        password: hashedPassword,

        profile_image: profileImageUrl,

        otp,

        otp_expiry: new Date(
          Date.now() + 10 * 60 * 1000
        ),

        is_verified: false,
      };

      if (user_type === "rider") {
        userData.rider_location = {
          lat: Number(latitude),
          lng: Number(longitude),
        };
      }

      /* 11. Create user */

      const newUser = await User.create(userData);

      createdUserId = newUser._id;

      /* 12. Send OTP */

      try {
        await sendOTP(normalizedEmail, otp);
      } catch (emailError) {
        console.error(
          "OTP email failed:",
          emailError.message
        );

        /*
          Remove the newly created, unverified account
          if its verification email cannot be sent.
        */

        await User.deleteOne({
          _id: newUser._id,
          is_verified: false,
        });

        createdUserId = null;

        if (uploadedDriveFileId) {
          try {
            await drive.files.delete({
              fileId: uploadedDriveFileId,
            });

            uploadedDriveFileId = null;
          } catch (cleanupError) {
            console.error(
              "Google Drive cleanup failed:",
              cleanupError.message
            );
          }
        }

        return res.status(502).json({
          status: "otp_email_failed",
          message: "Unable to send your OTP email.",
        });
      }

      /* 13. Return success */

      return res.status(201).json({
        status: "signup_success_otp_sent",

        message: "OTP sent successfully.",

        profile_image: profileImageUrl,
      });
    } catch (error) {
      console.error("Signup error:", error);

      /*
        Clean up a Google Drive upload if the user
        wasn't successfully created.
      */

      if (uploadedDriveFileId && !createdUserId) {
        try {
          await drive.files.delete({
            fileId: uploadedDriveFileId,
          });
        } catch (cleanupError) {
          console.error(
            "Google Drive cleanup failed:",
            cleanupError.message
          );
        }
      }

      return res.status(500).json({
        status: "error",
        message: "Signup failed. Please try again.",
      });
    }
  }
);

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

/* ============================================
   GET ALL ADMIN ACCOUNTS
   GET /admin/admins
============================================ */

app.get("/admin/admins", async (req, res) => {
  try {
    const admins = await Admin.find({})
      .select("-password -otp -otp_expiry")
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json({
      status: "success",
      count: admins.length,
      admins,
    });
  } catch (error) {
    console.error("Get admins error:", error);

    return res.status(500).json({
      status: "error",
      message: "Unable to retrieve administrator accounts.",
    });
  }
});

// PATCH: Activate or deactivate an admin
app.patch("/admin/admins/:adminId/status", async (req, res) => {
  try {
    const { adminId } = req.params;
    const { is_active } = req.body;

    // Validate admin ID
    if (!mongoose.Types.ObjectId.isValid(adminId)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid admin ID.",
      });
    }

    // Validate status
    if (typeof is_active !== "boolean") {
      return res.status(400).json({
        status: "error",
        message: "is_active must be true or false.",
      });
    }

    // Find admin
    const admin = await Admin.findById(adminId);

    if (!admin) {
      return res.status(404).json({
        status: "error",
        message: "Admin not found.",
      });
    }

    // Update status
    admin.is_active = is_active;
    await admin.save();

    return res.status(200).json({
      status: "success",
      message: `Admin ${is_active ? "activated" : "deactivated"} successfully.`,
      admin: {
        _id: admin._id,
        username: admin.username,
        email: admin.email,
        is_active: admin.is_active,
      },
    });
  } catch (error) {
    console.error("Update Admin Status Error:", error);

    return res.status(500).json({
      status: "error",
      message: "Failed to update admin status.",
    });
  }
});

// ==========================================
// GET COMBINED ADMIN DIRECTORY
// ==========================================

app.get("/admin/dashboard/directory", async (req, res) => {
  try {
    const [users, admins, riders] = await Promise.all([
      User.find({})
        .select("-password -otp -otp_expiry")
        .sort({ createdAt: -1 })
        .lean(),

      Admin.find({})
        .select("-password -otp -otp_expiry")
        .sort({ createdAt: -1 })
        .lean(),

      BecomeRider.find({})
        .select("-password -otp -otp_expiry")
        .sort({ createdAt: -1 })
        .lean(),
    ]);

    return res.status(200).json({
      status: "success",
      message: "Directory fetched successfully.",
      data: { users, admins, riders },
      counts: {
        users: users.length,
        admins: admins.length,
        riders: riders.length,
        total: users.length + admins.length + riders.length,
      },
    });
  } catch (error) {
    console.error("Admin Directory API Error:", error);

    return res.status(500).json({
      status: "error",
      message: "Failed to fetch directory.",
    });
  }
});

// TEMPORARY DEPLOYMENT DIAGNOSTIC
app.get("/admin/dashboard/route-check", (req, res) => {
  return res.status(200).json({
    status: "success",
    message: "Latest DWJD backend deployment is running.",
    route: "/admin/dashboard/route-check",
  });
});

// ============================================
// DWJD - COMPLETE ADMIN CSV REPORT EXPORTS
// ============================================

const REPORT_EXPORTS = {
  users: {
    model: User,
    filename: "dwjd-registered-users.csv",
    accountType: "registered_user",
  },

  donations: {
    model: Donation,
    filename: "dwjd-donations.csv",
    accountType: null,
  },

  riders: {
    // Actual rider accounts are stored in User.
    model: User,
    filename: "dwjd-riders.csv",
    accountType: "rider",
    filter: { user_type: "rider" },
  },

  "rider-requests": {
    model: BecomeRider,
    filename: "dwjd-rider-requests.csv",
    accountType: null,
  },

  admins: {
    model: Admin,
    filename: "dwjd-administrators.csv",
    accountType: null,
  },
};

// Fields that must never appear in CSV exports.
const REPORT_PRIVATE_FIELDS = new Set([
  "username",
  "password",
  "confirm_password",
  "otp",
  "otp_expiry",
  "resetPasswordToken",
  "resetPasswordExpires",
  "passwordResetToken",
  "passwordResetExpires",
  "refreshToken",
  "accessToken",
  "token",
  "__v",
]);

// Convert database values into readable CSV values.
const reportCSVValue = (value) => {
  if (value === null || value === undefined) {
    return "";
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value)) {
    value = value
      .map((item) =>
        typeof item === "object" && item !== null
          ? JSON.stringify(item)
          : String(item)
      )
      .join("; ");
  } else if (
    typeof value === "object" &&
    value !== null
  ) {
    value = JSON.stringify(value);
  }

  let text = String(value);

  // Prevent CSV formula injection when opening files
  // in Excel or similar spreadsheet applications.
  if (/^[\s]*[=+\-@]/.test(text)) {
    text = `'${text}`;
  }

  // Escape embedded double quotes.
  return `"${text.replace(/"/g, '""')}"`;
};

const buildReportCSV = (records) => {
  if (!records.length) {
    return "No records found.\r\n";
  }

  // Union of record fields, excluding sensitive fields.
  const columns = [
    ...new Set(
      records.flatMap((record) => Object.keys(record))
    ),
  ].filter(
    (field) => !REPORT_PRIVATE_FIELDS.has(field)
  );

  const header = columns
    .map((column) => reportCSVValue(column))
    .join(",");

  const rows = records.map((record) =>
    columns
      .map((column) => reportCSVValue(record[column]))
      .join(",")
  );

  return [header, ...rows].join("\r\n") + "\r\n";
};

// GET /admin/reports/export/:type
app.get(
  "/admin/reports/export/:type",
  requireGMForReports,
  async (req, res) => {
    try {
      const type = req.params.type;
      const config = REPORT_EXPORTS[type];

      if (!config) {
        return res.status(400).json({
          status: "error",
          message: "Unsupported report type.",
        });
      }

      let query = config.filter || {};

      // Distinguish regular users from rider accounts.
      if (type === "users") {
        query = { user_type: "user" };
      }

      const records = await config.model
        .find(query)
        .select(
          "-password -username -otp -otp_expiry -resetPasswordToken -resetPasswordExpires -passwordResetToken -passwordResetExpires -refreshToken -accessToken -token -__v"
        )
        .sort({ createdAt: -1 })
        .lean();

      const csv = buildReportCSV(records);

      res.setHeader(
        "Content-Type",
        "text/csv; charset=utf-8"
      );

      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${config.filename}"`
      );

      res.setHeader(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private"
      );

      // UTF-8 BOM helps Excel display text correctly.
      return res.status(200).send("\uFEFF" + csv);
    } catch (error) {
      console.error(
        "Admin CSV export error:",
        error
      );

      return res.status(500).json({
        status: "error",
        message: "Unable to export this report.",
      });
    }
  }
);
// ============================================
// DWJD - ADMIN REPORTS OVERVIEW
// GET /admin/reports/overview
// ============================================

app.get(
  "/admin/reports/overview",
  requireGMForReports,
  async (req, res) => {
    try {
      const [
        totalUsers,
        totalRiders,
        totalDonations,
        totalRiderRequests,
        totalAdmins,
        totalActiveAdmins,
      ] = await Promise.all([
        // Registered users excluding rider accounts
        User.countDocuments({
          user_type: "user",
        }),

        // Actual rider accounts
        User.countDocuments({
          user_type: "rider",
        }),

        // Donation records
        Donation.countDocuments({}),

        // Rider applications
        BecomeRider.countDocuments({}),

        // Administrator accounts
        Admin.countDocuments({}),

        // Active administrator accounts
        Admin.countDocuments({
          is_active: true,
        }),
      ]);

      return res.status(200).json({
        status: "success",
        message: "Reports overview retrieved successfully.",

        stats: {
          users: totalUsers,
          riders: totalRiders,
          donations: totalDonations,
          riderRequests: totalRiderRequests,
          admins: totalAdmins,
          activeAdmins: totalActiveAdmins,
        },
      });
    } catch (error) {
      console.error(
        "Admin Reports Overview Error:",
        error
      );

      return res.status(500).json({
        status: "error",
        message: "Unable to retrieve reports overview.",
      });
    }
  }
);

// ============================================
// RIDER MANAGEMENT AUTHORIZATION
// ============================================

const requireRiderManagementAccess = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;

    if (!authorization?.startsWith("Bearer ")) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Please log in as an administrator.",
      });
    }

    const token = authorization.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Authentication token is missing.",
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (!decoded.id || decoded.admin !== true) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Invalid administrator session.",
      });
    }

    const admin = await Admin.findById(decoded.id)
      .select("-password -otp -otp_expiry")
      .lean();

    if (!admin) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Administrator account not found.",
      });
    }

    if (!admin.is_active) {
      return res.status(403).json({
        status: "forbidden",
        message: "Your administrator account is inactive.",
      });
    }

    const roles = Array.isArray(admin.roles)
      ? admin.roles.map((role) =>
          String(role).toLowerCase()
        )
      : [];

    const userType = String(
      admin.user_type || ""
    ).toLowerCase();

    const permitted =
      userType === "gm" ||
      roles.includes("gm") ||
      roles.includes("customersupport");

    if (!permitted) {
      return res.status(403).json({
        status: "forbidden",
        message:
          "You do not have permission to manage rider requests.",
      });
    }

    req.riderManager = {
      id: String(admin._id),
      username: admin.username,
      roles,
      userType,
    };

    return next();
  } catch (error) {
    if (
      error.name === "JsonWebTokenError" ||
      error.name === "TokenExpiredError" ||
      error.name === "NotBeforeError"
    ) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Your session is invalid or has expired.",
      });
    }

    console.error("Rider authorization error:", error);

    return res.status(500).json({
      status: "error",
      message: "Unable to verify administrator permissions.",
    });
  }
};

// ============================================
// GET RIDER REQUESTS
// GET /admin/rider-requests
// ============================================

app.get(
  "/admin/rider-requests",
  requireRiderManagementAccess,
  async (req, res) => {
    try {
      const requests = await BecomeRider.find({})
        .populate(
          "reviewed_by",
          "username first_name last_name"
        )
        .populate(
          "created_user_id",
          "first_name last_name email user_type"
        )
        .sort({ createdAt: -1 })
        .lean();

      return res.status(200).json({
        status: "success",
        message: "Rider requests retrieved successfully.",
        count: requests.length,
        requests,
      });
    } catch (error) {
      console.error("Get rider requests error:", error);

      return res.status(500).json({
        status: "error",
        message: "Unable to retrieve rider requests.",
      });
    }
  }
);

// ============================================
// REVIEW RIDER REQUEST
// PATCH /admin/rider-requests/:requestId/status
// ============================================

app.patch(
  "/admin/rider-requests/:requestId/status",
  requireRiderManagementAccess,
  async (req, res) => {
    try {
      const { requestId } = req.params;
      const { status, rejection_reason } = req.body;

      if (!mongoose.Types.ObjectId.isValid(requestId)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid rider request ID.",
        });
      }

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({
          status: "error",
          message: "Status must be approved or rejected.",
        });
      }

      if (
        status === "rejected" &&
        !String(rejection_reason || "").trim()
      ) {
        return res.status(400).json({
          status: "error",
          message: "Please provide a reason for rejection.",
        });
      }

      // Update only applications that have not already
      // been approved, rejected, or converted into accounts.
      const updatedRequest = await BecomeRider.findOneAndUpdate(
        {
          _id: requestId,
          status: {
            $in: ["pending", "under_review"],
          },
        },
        {
          $set: {
            status,
            reviewed_by: req.riderManager.id,
            reviewed_at: new Date(),
            rejection_reason:
              status === "rejected"
                ? String(rejection_reason).trim()
                : "",
          },
        },
        {
          new: true,
          runValidators: true,
        }
      );

      if (!updatedRequest) {
        const existingRequest =
          await BecomeRider.findById(requestId);

        if (!existingRequest) {
          return res.status(404).json({
            status: "error",
            message: "Rider request not found.",
          });
        }

        return res.status(409).json({
          status: "error",
          message:
            `This request cannot be reviewed because its current status is "${existingRequest.status}".`,
        });
      }

      return res.status(200).json({
        status: "success",
        message:
          status === "approved"
            ? "Rider request approved successfully."
            : "Rider request rejected successfully.",
        request: updatedRequest,
      });
    } catch (error) {
      console.error("Review rider request error:", error);

      return res.status(500).json({
        status: "error",
        message: "Unable to update rider request.",
      });
    }
  }
);

// ============================================
// CREATE RIDER ACCOUNT FROM APPROVED REQUEST
// POST /admin/rider-requests/:requestId/create-account
// ============================================

app.post(
  "/admin/rider-requests/:requestId/create-account",
  requireRiderManagementAccess,
  async (req, res) => {
    let createdUserId = null;

    try {
      // ============================================
      // 1. VALIDATE REQUEST ID
      // ============================================

      const { requestId } = req.params;

      if (!mongoose.Types.ObjectId.isValid(requestId)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid rider request ID.",
        });
      }

      // ============================================
      // 2. FIND RIDER APPLICATION
      // ============================================

      const riderRequest = await BecomeRider.findById(requestId);

      if (!riderRequest) {
        return res.status(404).json({
          status: "error",
          message: "Rider request not found.",
        });
      }

      // ============================================
      // 3. CHECK WHETHER ACCOUNT ALREADY EXISTS
      // ============================================

      if (riderRequest.status === "account_created") {
        return res.status(409).json({
          status: "error",
          message: "A rider account has already been created.",
          rider_id: riderRequest.created_user_id,
        });
      }

      // ============================================
      // 4. REQUIRE APPROVAL
      // ============================================

      if (riderRequest.status !== "approved") {
        return res.status(409).json({
          status: "error",
          message:
            "Approve the rider request before creating an account.",
        });
      }

      const email = riderRequest.email.trim().toLowerCase();

      // ============================================
      // 5. CHECK FOR EXISTING USER EMAIL
      // ============================================

      const existingUser = await User.findOne({ email });

      if (existingUser) {
        return res.status(409).json({
          status: "error",
          message:
            "An account already exists with this email address. Review the existing account before proceeding.",
        });
      }

      // ============================================
      // 6. GENERATE A UNIQUE USERNAME
      // ============================================

      const emailPrefix = email
        .split("@")[0]
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "")
        .slice(0, 20);

      let username = emailPrefix || "rider";

      let usernameExists = await User.exists({ username });

      while (usernameExists) {
        username = `${emailPrefix || "rider"}${crypto.randomInt(
          1000,
          100000
        )}`;

        usernameExists = await User.exists({ username });
      }

      // ============================================
      // 7. GENERATE DEFAULT PASSWORD
      // ============================================

      const defaultPassword = crypto
        .randomBytes(18)
        .toString("base64url");

      // Hash the password before storing it.
      const hashedPassword = await bcrypt.hash(
        defaultPassword,
        12
      );

      // ============================================
      // 8. CREATE RIDER IN USER COLLECTION
      // ============================================

      const rider = await User.create({
        username,
        email,
        password: hashedPassword,

        first_name: riderRequest.first_name,
        last_name: riderRequest.last_name,
        phone: riderRequest.phone,

        user_type: "rider",

        profile_image: "",
        is_verified: false,
        is_active: true,

        otp: null,
        otp_expiry: null,
      });

      createdUserId = rider._id;

      // ============================================
      // 9. LINK RIDER TO APPLICATION
      // ============================================

      const updatedRequest = await BecomeRider.findOneAndUpdate(
        {
          _id: requestId,
          status: "approved",
          created_user_id: null,
        },
        {
          $set: {
            status: "account_created",
            created_user_id: rider._id,
            account_created_at: new Date(),
          },
        },
        {
          new: true,
          runValidators: true,
        }
      );

      // If another operation changed the request,
      // remove the account created by this operation.
      if (!updatedRequest) {
        await User.deleteOne({ _id: rider._id });

        createdUserId = null;

        return res.status(409).json({
          status: "error",
          message:
            "The request changed during account creation. Refresh the page and try again.",
        });
      }

      // ============================================
      // 10. SEND LOGIN CREDENTIALS THROUGH EMAIL
      // ============================================

      try {
        await sendEmail({
          to: email,

          subject: "Welcome to DWJD - Your Rider Account",

          html: `
            <!DOCTYPE html>
            <html>
              <body
                style="
                  margin: 0;
                  padding: 24px;
                  background: #f1f5f9;
                  font-family: Arial, sans-serif;
                  color: #1e293b;
                "
              >
                <div
                  style="
                    max-width: 600px;
                    margin: auto;
                    overflow: hidden;
                    background: #ffffff;
                    border-radius: 14px;
                    border: 1px solid #e2e8f0;
                  "
                >
                  <div
                    style="
                      padding: 28px;
                      text-align: center;
                      background: #0f172a;
                      color: #ffffff;
                    "
                  >
                    <h1 style="margin: 0;">DWJD</h1>
                    <p style="margin-bottom: 0;">
                      Rider Account Created
                    </p>
                  </div>

                  <div style="padding: 28px;">
                    <h2>
                      Hello ${escapeHtml(rider.first_name)},
                    </h2>

                    <p>
                      Your DWJD rider account has been created
                      successfully.
                    </p>

                    <div
                      style="
                        padding: 20px;
                        background: #f8fafc;
                        border: 1px solid #e2e8f0;
                        border-radius: 10px;
                      "
                    >
                      <p>
                        <strong>Username:</strong>
                        ${escapeHtml(rider.username)}
                      </p>

                      <p>
                        <strong>Default password:</strong>
                        ${escapeHtml(defaultPassword)}
                      </p>

                      <p>
                        <strong>Account type:</strong>
                        Rider
                      </p>
                    </div>

                    <p style="margin-top: 24px;">
                      Keep your login credentials confidential.
                      Change your default password after signing in.
                    </p>

                    <p>
                      Your account may require email verification
                      before you can log in.
                    </p>

                    <p>
                      Regards,<br />
                      <strong>DWJD Team</strong>
                    </p>
                  </div>
                </div>
              </body>
            </html>
          `,
        });

        // ============================================
        // 11. SUCCESS RESPONSE
        // ============================================

        return res.status(201).json({
          status: "rider_created",

          message:
            "Rider account created successfully. Login credentials have been emailed.",

          rider: {
            id: rider._id,
            username: rider.username,
            email: rider.email,
            first_name: rider.first_name,
            last_name: rider.last_name,
            user_type: rider.user_type,
          },

          request: {
            id: updatedRequest._id,
            status: updatedRequest.status,
          },

          email_sent: true,
        });
      } catch (emailError) {
        // The account already exists and is linked.
        // Do not delete it or create another account.

        console.error(
          "Rider credentials email failed:",
          emailError.message
        );

        return res.status(201).json({
          status: "rider_created_email_failed",

          message:
            "The rider account was created, but the credentials email could not be sent. Use a secure password-reset process to restore access.",

          rider: {
            id: rider._id,
            username: rider.username,
            email: rider.email,
            first_name: rider.first_name,
            last_name: rider.last_name,
            user_type: rider.user_type,
          },

          request: {
            id: updatedRequest._id,
            status: updatedRequest.status,
          },

          email_sent: false,
        });
      }
    } catch (error) {
      // ============================================
      // 12. HANDLE UNEXPECTED ERRORS
      // ============================================

      console.error("Create rider account error:", error);

      // Best-effort cleanup if the account was created
      // but was not linked to the application.
      if (createdUserId) {
        try {
          const linkedRequest = await BecomeRider.findOne({
            created_user_id: createdUserId,
            status: "account_created",
          });

          if (!linkedRequest) {
            await User.deleteOne({
              _id: createdUserId,
            });
          }
        } catch (cleanupError) {
          console.error(
            "Rider account cleanup error:",
            cleanupError
          );
        }
      }

      if (error.code === 11000) {
        return res.status(409).json({
          status: "error",
          message:
            "An account with this email or username already exists.",
        });
      }

      return res.status(500).json({
        status: "error",
        message: "Unable to create the rider account.",
      });
    }
  }
);
/* =========================================
   GOOGLE DRIVE CONFIGURATION
========================================= */

const googleAuth = new google.auth.GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_CLIENT_EMAIL,

    private_key: process.env.GOOGLE_PRIVATE_KEY?.replace(
      /\\n/g,
      "\n"
    ),
  },

  scopes: [
    "https://www.googleapis.com/auth/drive",
  ],
});

const drive = google.drive({
  version: "v3",
  auth: googleAuth,
});


/* =========================================
   MULTER CONFIGURATION
========================================= */

const profileUpload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 1,
  },

  fileFilter: (req, file, callback) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp",
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return callback(
        new Error(
          "Only JPEG, PNG, and WEBP images are allowed."
        )
      );
    }

    callback(null, true);
  },
});


/* =========================================
   GOOGLE DRIVE UPLOAD FUNCTION
========================================= */

async function uploadProfileImage(file, userType) {
  const folderId =
    userType === "rider"
      ? process.env.GOOGLE_DRIVE_RIDERS_FOLDER_ID
      : process.env.GOOGLE_DRIVE_CUSTOMERS_FOLDER_ID;

  if (!folderId) {
    throw new Error(
      `Google Drive folder ID is missing for ${userType}.`
    );
  }

  const extensionByMimeType = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
  };

  const extension = extensionByMimeType[file.mimetype];

  if (!extension) {
    throw new Error("Unsupported image format.");
  }

  const fileName =
    `profile_${Date.now()}_${crypto.randomBytes(6).toString("hex")}.${extension}`;

  const uploadedFile = await drive.files.create({
    requestBody: {
      name: fileName,
      mimeType: file.mimetype,
      parents: [folderId],
    },

    media: {
      mimeType: file.mimetype,
      body: Readable.from(file.buffer),
    },

    fields: "id, name",
  });

  const fileId = uploadedFile.data.id;

  try {
    /*
      Public link access is enabled here so the URL can
      be displayed directly in an HTML img element.

      Only use this if public profile pictures are acceptable
      for your application.
    */

    await drive.permissions.create({
      fileId,

      requestBody: {
        type: "anyone",
        role: "reader",
      },
    });

    return {
      fileId,

      url:
        `https://drive.google.com/uc?export=view&id=${fileId}`,
    };
  } catch (error) {
    try {
      await drive.files.delete({
        fileId,
      });
    } catch (cleanupError) {
      console.error(
        "Google Drive cleanup failed:",
        cleanupError.message
      );
    }

    throw error;
  }
}
/* ================= SERVER START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));