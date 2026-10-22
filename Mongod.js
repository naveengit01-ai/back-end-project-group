require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const crypto = require("crypto");
const cron = require("node-cron");
const multer = require("multer");
const { google } = require("googleapis");
const { Readable } = require("stream");
const Razorpay = require("razorpay");
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
app.use(
  express.json({
    limit: "8mb",
    verify: (req, res, buf) => {
      if (req.originalUrl === "/webhooks/razorpay") {
        req.rawBody = Buffer.from(buf);
      }
    },
  })
);
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
/* ============================================
   GENERAL ADMIN AUTHENTICATION
   Used by admin advertisement management APIs
============================================ */

const requireAdmin = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
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

    // Verify the JWT using the same secret as admin login.
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Your /admin/login API creates tokens with admin: true.
    if (!decoded.id || decoded.admin !== true) {
      return res.status(403).json({
        status: "forbidden",
        message: "Administrator access is required.",
      });
    }

    // Verify that the admin still exists in MongoDB.
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

    // Store authenticated administrator information.
    req.admin = {
      id: String(admin._id),
      username: admin.username,
      roles: Array.isArray(admin.roles) ? admin.roles : [],
      user_type: admin.user_type,
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

    console.error("Admin authentication error:", error);

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

function getProfileImageUrl(imageUrl) {
  if (!imageUrl || typeof imageUrl !== "string") {
    return "";
  }

  try {
    const parsedUrl = new URL(imageUrl);

    // Support Google Drive image URLs.
    const isGoogleDrive =
      parsedUrl.hostname === "drive.google.com" ||
      parsedUrl.hostname === "docs.google.com" ||
      parsedUrl.hostname === "lh3.googleusercontent.com";

    if (!isGoogleDrive) {
      return imageUrl;
    }

    let fileId = parsedUrl.searchParams.get("id");

    // Handle URLs such as:
    // drive.google.com/file/d/FILE_ID/view
    if (!fileId) {
      const match = parsedUrl.pathname.match(
        /\/file\/d\/([^/]+)/
      );

      if (match) {
        fileId = match[1];
      }
    }

    // Handle Google thumbnail URLs containing the ID in /d/FILE_ID.
    if (!fileId) {
      const match = parsedUrl.pathname.match(
        /\/d\/([^/]+)/
      );

      if (match) {
        fileId = match[1];
      }
    }

    if (!fileId) {
      return imageUrl;
    }

    return `https://drive.google.com/thumbnail?id=${encodeURIComponent(
      fileId
    )}&sz=w400`;
  } catch (error) {
    console.error("Profile image URL parsing failed:", error.message);
    return imageUrl;
  }
}

app.post("/get-user-by-email", async (req, res) => {
  try {
    const { email } = req.body;

    // 1. Validate email.
    if (!email || typeof email !== "string") {
      return res.status(400).json({
        status: "missing_fields",
        message: "Email is required.",
      });
    }

    // 2. Normalize email.
    const normalizedEmail = email.trim().toLowerCase();

    // 3. Retrieve user from MongoDB.
    const user = await User.findOne({
      email: normalizedEmail,
    }).select("-password -otp -otp_expiry -__v");

    // 4. Check whether user exists.
    if (!user) {
      return res.status(404).json({
        status: "not_found",
        message: "User not found.",
      });
    }

    // 5. Normalize the profile image URL.
    const profileImageUrl = getProfileImageUrl(
      user.profile_image
    );

    // 6. Return user details.
    return res.status(200).json({
      status: "success",
      message: "User details retrieved successfully.",

      user: {
        _id: user._id,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        phone: user.phone,

        profile_image: profileImageUrl,

        user_type: user.user_type,
        is_rider_approved: user.is_rider_approved,
        is_verified: user.is_verified,
        is_active: user.is_active,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  } catch (err) {
    console.error("Get user error:", err);

    return res.status(500).json({
      status: "error",
      message:
        "An internal server error occurred while retrieving user details.",
    });
  }
});
app.put("/update-profile", async (req, res) => {
  try {
    const { email, first_name, last_name, phone } = req.body;

    // 1. Validate email
    if (!email || typeof email !== "string") {
      return res.status(400).json({
        status: "missing_email",
        message: "Email is required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // 2. Find the user
    const user = await User.findOne({
      email: normalizedEmail,
    });

    if (!user) {
      return res.status(404).json({
        status: "not_found",
        message: "User not found.",
      });
    }

    // 3. Validate and update editable fields
    if (first_name !== undefined) {
      if (typeof first_name !== "string" || !first_name.trim()) {
        return res.status(400).json({
          status: "invalid_first_name",
          message: "First name cannot be empty.",
        });
      }

      user.first_name = first_name.trim();
    }

    if (last_name !== undefined) {
      if (typeof last_name !== "string" || !last_name.trim()) {
        return res.status(400).json({
          status: "invalid_last_name",
          message: "Last name cannot be empty.",
        });
      }

      user.last_name = last_name.trim();
    }

    if (phone !== undefined) {
      if (typeof phone !== "string" || !phone.trim()) {
        return res.status(400).json({
          status: "invalid_phone",
          message: "Phone number cannot be empty.",
        });
      }

      user.phone = phone.trim();
    }

    // 4. Save changes
    await user.save();

    // 5. Return safe user data
    const safeUser = {
      _id: user._id,
      username: user.username,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      phone: user.phone,
      profile_image: user.profile_image || "",
      user_type: user.user_type,
      is_verified: user.is_verified,
      is_active: user.is_active,
    };

    return res.status(200).json({
      status: "updated_successfully",
      message: "Profile updated successfully.",
      user: safeUser,
    });
  } catch (err) {
    console.error("Update profile error:", err);

    return res.status(500).json({
      status: "error",
      message: "An internal server error occurred while updating your profile.",
    });
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

// ======================================================
// BECOME RIDER: SUBMIT ACCOUNT REQUEST
// POST /rider/request-account
//
// Camera photo -> Google Drive -> MongoDB
// ======================================================

app.post("/rider/request-account", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      phone,
      profile_image_data,
    } = req.body || {};

    // ==================================================
    // 1. VALIDATE REQUIRED FIELDS
    // ==================================================

    if (
      typeof first_name !== "string" ||
      typeof last_name !== "string" ||
      typeof email !== "string" ||
      typeof phone !== "string" ||
      !first_name.trim() ||
      !last_name.trim() ||
      !email.trim() ||
      !phone.trim()
    ) {
      return res.status(400).json({
        status: "missing_fields",
        message: "Please fill in all required fields.",
      });
    }

    const normalizedFirstName = first_name.trim();
    const normalizedLastName = last_name.trim();
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim();

    // ==================================================
    // 2. VALIDATE EMAIL
    // ==================================================

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        status: "invalid_email",
        message: "Please enter a valid email address.",
      });
    }

    // ==================================================
    // 3. VALIDATE PHONE NUMBER
    // ==================================================

    // Supports international numbers such as +919876543210.

    const normalizedPhoneDigits = normalizedPhone.replace(
      /[\s()-]/g,
      ""
    );

    if (!/^\+?\d{10,15}$/.test(normalizedPhoneDigits)) {
      return res.status(400).json({
        status: "invalid_phone",
        message: "Please enter a valid mobile number.",
      });
    }

    // ==================================================
    // 4. VALIDATE CAMERA PHOTO DATA
    // ==================================================

    // The frontend sends:
    // data:image/jpeg;base64,<BASE64_IMAGE_DATA>

    if (
      typeof profile_image_data !== "string" ||
      !profile_image_data.startsWith("data:image/jpeg;base64,")
    ) {
      return res.status(400).json({
        status: "invalid_profile_image",
        message:
          "Please capture and confirm a profile photo using your camera.",
      });
    }

    // Extract the Base64 image data.

    const base64Match = profile_image_data.match(
      /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/
    );

    if (!base64Match) {
      return res.status(400).json({
        status: "invalid_profile_image",
        message: "The captured profile photo is invalid.",
      });
    }

    const imageBuffer = Buffer.from(base64Match[1], "base64");

    // Limit the decoded image to 5 MB.

    const MAX_IMAGE_SIZE = 5 * 1024 * 1024;

    if (
      imageBuffer.length === 0 ||
      imageBuffer.length > MAX_IMAGE_SIZE
    ) {
      return res.status(400).json({
        status: "invalid_profile_image",
        message:
          "The profile photo must be a valid image smaller than 5 MB.",
      });
    }

    // Verify that the decoded file begins with the JPEG signature.

    const isJpeg =
      imageBuffer.length >= 3 &&
      imageBuffer[0] === 0xff &&
      imageBuffer[1] === 0xd8 &&
      imageBuffer[2] === 0xff;

    if (!isJpeg) {
      return res.status(400).json({
        status: "invalid_profile_image",
        message: "Please submit a valid JPEG camera photo.",
      });
    }

    // ==================================================
    // 5. CHECK EXISTING RIDER ACCOUNT
    // ==================================================

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

    // ==================================================
    // 6. CHECK EXISTING RIDER REQUEST
    // ==================================================

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

    // ==================================================
    // 7. UPLOAD CAMERA PHOTO TO GOOGLE DRIVE
    // ==================================================

    // Convert the captured image into the file object
    // expected by your existing uploadProfileImage helper.

    const cameraPhotoFile = {
      buffer: imageBuffer,
      mimetype: "image/jpeg",
      originalname: "rider-profile.jpg",
      size: imageBuffer.length,
    };

    const uploadedImage = await uploadProfileImage(
      cameraPhotoFile,
      "rider"
    );

    // Make sure Google Drive returned a usable URL.

    if (
      !uploadedImage ||
      typeof uploadedImage.url !== "string" ||
      !uploadedImage.url.trim()
    ) {
      throw new Error(
        "Google Drive did not return a profile image URL."
      );
    }

    const normalizedProfileImage = uploadedImage.url.trim();

    console.log(
      "Rider profile photo uploaded successfully to Google Drive."
    );

    // ==================================================
    // 8. SAVE RIDER REQUEST TO MONGODB
    // ==================================================

    const riderRequest = await BecomeRider.create({
      first_name: normalizedFirstName,
      last_name: normalizedLastName,
      email: normalizedEmail,
      phone: normalizedPhoneDigits,

      // Save the Google Drive URL, NOT the Base64 image.
      profile_image: normalizedProfileImage,

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

    // ==================================================
    // 9. SEND CONFIRMATION EMAIL
    // ==================================================

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
                  <h1 style="margin: 0;">DWJD</h1>

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
                    <h3 style="color: #1d4ed8;">
                      What happens next?
                    </h3>

                    <p style="
                      color: #374151;
                      line-height: 1.7;
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
      // Do not delete the request if the email fails.

      console.error(
        "Rider request confirmation email failed:",
        emailError.message
      );
    }

    // ==================================================
    // 10. RETURN SUCCESS RESPONSE
    // ==================================================

    return res.status(201).json({
      status: "request_submitted",

      message:
        "Your rider account request has been submitted successfully. Our Customer Support team will review your request within 24 hours.",

      request_id: riderRequest._id,

      email_sent: emailSent,
    });
  } catch (error) {
    console.error(
      "Become Rider request error:",
      error
    );

    return res.status(500).json({
      status: "error",
      message:
        "We could not submit your request right now. Please try again later.",
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


const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_OAUTH_CLIENT_ID,
  process.env.GOOGLE_OAUTH_CLIENT_SECRET,
  process.env.GOOGLE_OAUTH_REDIRECT_URI
);

oauth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
});

const drive = google.drive({
  version: "v3",
  auth: oauth2Client,
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

/* =========================================================
   UPLOAD PROFILE PHOTO API
   Google Drive + MongoDB
========================================================= */

// Extract a Google Drive file ID from a stored URL.
function getGoogleDriveFileId(imageUrl) {
  if (!imageUrl || typeof imageUrl !== "string") {
    return null;
  }

  try {
    const parsedUrl = new URL(imageUrl);

    // Only process URLs belonging to Google Drive.
    const isGoogleDrive =
      parsedUrl.hostname === "drive.google.com" ||
      parsedUrl.hostname === "docs.google.com";

    if (!isGoogleDrive) {
      return null;
    }

    // Format:
    // https://drive.google.com/uc?export=view&id=FILE_ID
    const queryFileId = parsedUrl.searchParams.get("id");

    if (queryFileId) {
      return queryFileId;
    }

    // Format:
    // https://drive.google.com/file/d/FILE_ID/view
    const pathMatch = parsedUrl.pathname.match(
      /\/file\/d\/([^/]+)/
    );

    if (pathMatch) {
      return pathMatch[1];
    }

    return null;
  } catch (error) {
    console.error("Unable to extract Google Drive file ID:", error.message);
    return null;
  }
}


// Delete an old Google Drive profile photo.
async function deleteOldProfilePhoto(imageUrl, newFileId) {
  const oldFileId = getGoogleDriveFileId(imageUrl);

  // No valid Google Drive ID was found.
  if (!oldFileId) {
    console.log(
      "No previous Google Drive photo found. Skipping deletion."
    );

    return;
  }

  // Never delete the newly uploaded photo.
  if (oldFileId === newFileId) {
    console.log(
      "Old and new photo IDs match. Skipping deletion."
    );

    return;
  }

  try {
    await drive.files.delete({
      fileId: oldFileId,
    });

    console.log(
      "Previous profile photo deleted successfully:",
      oldFileId
    );
  } catch (error) {
    console.error(
      "Failed to delete previous Google Drive photo:",
      oldFileId,
      error.response?.data || error.message
    );

    // Do not throw here.
    // The new photo has already been saved successfully.
  }
}


// Profile photo upload endpoint.
app.post(
  "/upload-profile-photo",

  // Multer middleware with error handling.
  (req, res, next) => {
    profileUpload.single("photo")(req, res, (error) => {
      if (error) {
        console.error(
          "Profile photo validation error:",
          error.message
        );

        if (error.code === "LIMIT_FILE_SIZE") {
          return res.status(400).json({
            status: "file_too_large",
            message: "Profile photo must not exceed 5 MB.",
          });
        }

        if (error.code === "LIMIT_UNEXPECTED_FILE") {
          return res.status(400).json({
            status: "unexpected_file",
            message:
              'Unexpected file field. Use the field name "photo".',
          });
        }

        return res.status(400).json({
          status: "invalid_photo",
          message: error.message || "Invalid profile photo.",
        });
      }

      next();
    });
  },

  // Main upload handler.
  async (req, res) => {
    let uploadedFileId = null;

    try {
      /* -----------------------------------------
         1. Validate request
      ----------------------------------------- */

      const { email } = req.body;

      if (!email || typeof email !== "string") {
        return res.status(400).json({
          status: "missing_email",
          message: "Email is required.",
        });
      }

      if (!req.file) {
        return res.status(400).json({
          status: "missing_photo",
          message: "Please select a profile photo.",
        });
      }

      const normalizedEmail = email.trim().toLowerCase();

      /* -----------------------------------------
         2. Find the user
      ----------------------------------------- */

      const user = await User.findOne({
        email: normalizedEmail,
      });

      if (!user) {
        return res.status(404).json({
          status: "not_found",
          message: "User or rider account not found.",
        });
      }

      /* -----------------------------------------
         3. Store the old photo information
      ----------------------------------------- */

      const oldProfileImage = user.profile_image || null;

      /* -----------------------------------------
         4. Upload the new photo to Google Drive
      ----------------------------------------- */

      const uploadedImage = await uploadProfileImage(
        req.file,
        user.user_type
      );

      uploadedFileId = uploadedImage.fileId;

      if (!uploadedImage.fileId || !uploadedImage.url) {
        throw new Error(
          "Google Drive did not return the expected photo details."
        );
      }

      /* -----------------------------------------
         5. Update MongoDB with the new photo URL
      ----------------------------------------- */

      user.profile_image = uploadedImage.url;

      await user.save();

      // MongoDB now contains the new photo URL.
      // Do not delete the new photo if old-photo deletion fails.

      /* -----------------------------------------
         6. Delete the previous Google Drive photo
      ----------------------------------------- */

      if (oldProfileImage) {
        await deleteOldProfilePhoto(
          oldProfileImage,
          uploadedImage.fileId
        );
      }

      /* -----------------------------------------
         7. Send success response
      ----------------------------------------- */

      return res.status(200).json({
        status: "photo_uploaded",
        message: "Profile photo uploaded successfully.",

        user: {
          _id: user._id,
          first_name: user.first_name,
          last_name: user.last_name,
          email: user.email,
          profile_image: user.profile_image,
        },
      });
    } catch (error) {
      console.error(
        "Profile photo upload error:",
        error.response?.data || error.message
      );

      /* -----------------------------------------
         8. Clean up the new photo if the operation
            failed before completing successfully
      ----------------------------------------- */

      if (uploadedFileId) {
        try {
          await drive.files.delete({
            fileId: uploadedFileId,
          });

          console.log(
            "Newly uploaded photo cleaned up:",
            uploadedFileId
          );
        } catch (cleanupError) {
          console.error(
            "New photo cleanup failed:",
            cleanupError.response?.data ||
              cleanupError.message
          );
        }
      }

      return res.status(500).json({
        status: "upload_failed",
        message: "Unable to upload your profile photo.",
      });
    }
  }
);
const promotionUpload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 50 * 1024 * 1024, // Maximum 50 MB per file
    files: 2,
    fields: 30,
    fieldSize: 1024 * 1024,
  },

  fileFilter: (req, file, callback) => {
    const allowedTypes = {
      banner: ["image/jpeg", "image/png", "image/webp"],
      video: ["video/mp4", "video/webm", "video/quicktime"],
    };

    if (!allowedTypes[file.fieldname]) {
      return callback(new Error("Unexpected upload field."));
    }

    if (!allowedTypes[file.fieldname].includes(file.mimetype)) {
      return callback(
        new Error(
          file.fieldname === "banner"
            ? "Banner must be JPG, PNG, or WEBP."
            : "Video must be MP4, WEBM, or MOV."
        )
      );
    }

    callback(null, true);
  },
});
async function uploadPromotionFileToDrive(file, title) {
  const folderId =
    process.env.GOOGLE_DRIVE_ADVERTISEMENTS_FOLDER_ID;

  if (!folderId) {
    throw new Error(
      "Google Drive advertisements folder is not configured."
    );
  }

  const extensions = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov",
  };

  const extension = extensions[file.mimetype];

  if (!extension) {
    throw new Error("Unsupported promotion file type.");
  }

  const safeTitle = String(title || "promotion")
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .slice(0, 48);

  const filename =
    `${safeTitle}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}.${extension}`;

  const uploaded = await drive.files.create({
    requestBody: {
      name: filename,
      mimeType: file.mimetype,
      parents: [folderId],
    },

    media: {
      mimeType: file.mimetype,
      body: Readable.from(file.buffer),
    },

    fields: "id,name",
  });

  const fileId = uploaded.data.id;

  try {
    // Only use public link access for assets intended to be public.
    await drive.permissions.create({
      fileId,
      requestBody: {
        type: "anyone",
        role: "reader",
      },
    });
  } catch (error) {
    try {
      await drive.files.delete({ fileId });
    } catch (cleanupError) {
      console.error(
        "Drive cleanup failed:",
        cleanupError.message
      );
    }

    throw error;
  }

  return {
    fileId,
    url: `https://drive.google.com/uc?export=view&id=${fileId}`,
  };
}

app.post(
  "/advertisements/request",

  // Receive multipart form data.
  (req, res, next) => {
    promotionUpload.fields([
      { name: "banner", maxCount: 1 },
      { name: "video", maxCount: 1 },
    ])(req, res, (error) => {
      if (!error) {
        return next();
      }

      const tooLarge =
        error instanceof multer.MulterError &&
        error.code === "LIMIT_FILE_SIZE";

      return res.status(tooLarge ? 413 : 400).json({
        status: "error",
        message: tooLarge
          ? "An uploaded file exceeds the 50 MB limit."
          : error.message || "Unable to upload files.",
      });
    });
  },

  async (req, res) => {
    const uploadedFileIds = [];

    try {
      const {
        brand_name,
        company_name,
        contact_person,
        contact_email,
        contact_phone,
        company_website,
        title,
        description,
        promotion_type,
        target_url,
        placement,
        start_date,
        end_date,
        amount_paid,
        collaboration_type,
      } = req.body;

      // Validate required fields.
      const requiredFields = {
        brand_name,
        company_name,
        contact_person,
        contact_email,
        contact_phone,
        title,
        description,
        promotion_type,
        start_date,
        end_date,
        amount_paid,
      };

      const missingFields = Object.entries(requiredFields)
        .filter(
          ([, value]) =>
            value === undefined ||
            value === null ||
            String(value).trim() === ""
        )
        .map(([key]) => key);

      if (missingFields.length > 0) {
        return res.status(400).json({
          status: "error",
          message: `Missing fields: ${missingFields.join(", ")}`,
        });
      }

      // Validate email.
      const email = String(contact_email)
        .trim()
        .toLowerCase();

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
          status: "error",
          message: "Please enter a valid business email.",
        });
      }

      // Validate budget.
      const budget = Number(amount_paid);

      if (!Number.isFinite(budget) || budget < 0) {
        return res.status(400).json({
          status: "error",
          message: "Budget must be a valid non-negative number.",
        });
      }

      // Validate campaign schedule.
      const startDate = new Date(start_date);
      const endDate = new Date(end_date);

      if (
        Number.isNaN(startDate.getTime()) ||
        Number.isNaN(endDate.getTime()) ||
        endDate <= startDate
      ) {
        return res.status(400).json({
          status: "error",
          message: "End date must be after the start date.",
        });
      }

      const allowedTypes = [
        "banner",
        "sponsored_post",
        "video",
        "product_promotion",
        "brand_awareness",
      ];

      const allowedPlacements = [
        "home_page",
        "donation_page",
        "pickup_page",
        "rider_dashboard",
        "all_pages",
      ];

      const allowedCollaborations = [
        "paid_promotion",
        "sponsorship",
        "brand_partnership",
      ];

      if (!allowedTypes.includes(promotion_type)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid promotion type.",
        });
      }

      if (
        placement &&
        !allowedPlacements.includes(placement)
      ) {
        return res.status(400).json({
          status: "error",
          message: "Invalid promotion placement.",
        });
      }

      if (
        collaboration_type &&
        !allowedCollaborations.includes(collaboration_type)
      ) {
        return res.status(400).json({
          status: "error",
          message: "Invalid collaboration type.",
        });
      }

      // Get uploaded files.
      const banner = req.files?.banner?.[0] || null;
      const video = req.files?.video?.[0] || null;

      // Additional banner size limit: 5 MB.
      if (banner && banner.size > 5 * 1024 * 1024) {
        return res.status(413).json({
          status: "error",
          message: "Banner image must be 5 MB or smaller.",
        });
      }

      // Validate optional URLs.
      const validateUrl = (value, label) => {
        if (!value) return "";

        let parsed;

        try {
          parsed = new URL(String(value));
        } catch {
          throw new Error(`${label} is not a valid URL.`);
        }

        if (!["http:", "https:"].includes(parsed.protocol)) {
          throw new Error(`${label} must use HTTP or HTTPS.`);
        }

        return parsed.toString();
      };

      let companyWebsite;
      let destinationUrl;

      try {
        companyWebsite = validateUrl(
          company_website,
          "Company website"
        );

        destinationUrl = validateUrl(
          target_url,
          "Destination URL"
        );
      } catch (error) {
        return res.status(400).json({
          status: "error",
          message: error.message,
        });
      }

      // Upload banner and video to Google Drive.
      let imageUrl = "";
      let videoUrl = "";

      if (banner) {
        const result = await uploadPromotionFileToDrive(
          banner,
          title
        );

        uploadedFileIds.push(result.fileId);
        imageUrl = result.url;
      }

      if (video) {
        const result = await uploadPromotionFileToDrive(
          video,
          title
        );

        uploadedFileIds.push(result.fileId);
        videoUrl = result.url;
      }

      // Save campaign in MongoDB.
      const advertisement = await Advertisement.create({
        brand_name: String(brand_name).trim(),
        company_name: String(company_name).trim(),
        contact_person: String(contact_person).trim(),
        contact_email: email,
        contact_phone: String(contact_phone).trim(),
        company_website: companyWebsite,

        title: String(title).trim(),
        description: String(description).trim(),
        promotion_type,

        image_url: imageUrl,
        video_url: videoUrl,
        target_url: destinationUrl,

        placement: placement || "home_page",

        start_date: startDate,
        end_date: endDate,

        amount_paid: budget,
        currency: "INR",
        payment_status: "pending",
        payment_reference: "",

        collaboration_type:
          collaboration_type || "paid_promotion",

        status: "pending",
        rejection_reason: "",
        reviewed_by: null,
        reviewed_at: null,

        is_active: false,
      });

      // Send confirmation email.
      // This assumes your existing sendEmail helper accepts
      // { to, subject, html }; adapt if its signature differs.
      let emailSent = false;

      try {
        const escapeHtml = (value) =>
          String(value).replace(/[&<>"']/g, (character) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
          })[character]);

        await sendEmail({
          to: email,
          subject: "DWJD received your brand promotion request",

          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:24px">
              <h1>DWJD — Brand Promotion Request</h1>

              <p>Hello ${escapeHtml(contact_person)},</p>

              <p>
                We received your promotion request for
                <strong>${escapeHtml(title)}</strong>.
              </p>

              <p>
                Our team will review your request within
                <strong>24 hours</strong> and contact you by email
                about the next steps and payment confirmation.
              </p>

              <p>
                Your request is pending review.
                Submission does not mean the campaign is approved
                or that payment has been received.
              </p>

              <p>Thank you,<br/>DWJD Team</p>
            </div>
          `,
        });

        emailSent = true;
      } catch (emailError) {
        console.error(
          "Promotion email failed:",
          emailError.message
        );
      }

      return res.status(201).json({
        status: "success",

        message: emailSent
          ? "Promotion request submitted. Check your email; DWJD will review it within 24 hours."
          : "Promotion request saved. Email delivery failed, but DWJD will review it within 24 hours.",

        email_sent: emailSent,

        advertisement: {
          _id: advertisement._id,
          brand_name: advertisement.brand_name,
          title: advertisement.title,
          image_url: advertisement.image_url,
          video_url: advertisement.video_url,
          status: advertisement.status,
          payment_status: advertisement.payment_status,
          is_active: advertisement.is_active,
          createdAt: advertisement.createdAt,
        },
      });
    } catch (error) {
      console.error(
        "Promotion submission error:",
        error
      );

      // Clean up files if the operation failed after uploading.
      for (const fileId of uploadedFileIds) {
        try {
          await drive.files.delete({ fileId });
        } catch (cleanupError) {
          console.error(
            "Google Drive cleanup failed:",
            cleanupError.message
          );
        }
      }

      if (error.name === "ValidationError") {
        return res.status(400).json({
          status: "error",
          message: error.message,
        });
      }

      return res.status(500).json({
        status: "error",
        message: "Unable to submit promotion request.",
      });
    }
  }
);
/* ============================================
   ADMIN ADVERTISEMENT MANAGEMENT
============================================ */

/* ============================================
   RAZORPAY CONFIGURATION
============================================ */

if (
  !process.env.RAZORPAY_KEY_ID ||
  !process.env.RAZORPAY_KEY_SECRET
) {
  console.warn(
    "Razorpay configuration is missing. Payment-link creation will fail until credentials are configured."
  );
}

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});
/* ============================================
   ADMIN: GET ALL ADVERTISEMENTS
   GET /admin/advertisements
============================================ */

app.get(
  "/admin/advertisements",
  requireAdmin,
  async (req, res) => {
    try {
      // Fetch all advertisements, newest first.
      const advertisements = await Advertisement.find({})
        .populate("reviewed_by", "username email")
        .sort({ createdAt: -1 })
        .lean();

      return res.status(200).json({
        status: "success",
        count: advertisements.length,

        advertisements: advertisements.map((ad) => ({
          ...ad,

          // Campaign approval details
          status: ad.status || "pending",
          rejection_reason: ad.rejection_reason || "",
          reviewed_at: ad.reviewed_at || null,
          reviewed_by: ad.reviewed_by || null,

          // Payment details
          payment_status: ad.payment_status || "pending",
          approved_amount: ad.approved_amount ?? null,
          currency: ad.currency || "INR",

          // Razorpay payment-link details
          payment_link_id: ad.payment_link_id || "",
          payment_link_url: ad.payment_link_url || "",
          payment_link_sent_at: ad.payment_link_sent_at || null,

          // Verified payment details
          payment_reference: ad.payment_reference || "",
          payment_paid_at: ad.payment_paid_at || null,

          // Activation
          is_active: ad.is_active === true,
        })),
      });
    } catch (error) {
      console.error("Fetch advertisements error:", error);

      return res.status(500).json({
        status: "error",
        message: "Failed to fetch advertisements.",
      });
    }
  }
);

/* ============================================
   ADMIN: APPROVE PROMOTION
   PATCH /admin/advertisements/:id/approve

   Request body:
   {
     "approved_amount": 5000,
     "currency": "INR"
   }
============================================ */

app.patch(
  "/admin/advertisements/:id/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { approved_amount, currency = "INR" } = req.body;

      // 1. Validate the promotion ID.
      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid promotion ID.",
        });
      }

      // 2. Validate the approved amount.
      const amount = Number(approved_amount);

      if (
        approved_amount === undefined ||
        approved_amount === null ||
        approved_amount === "" ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          status: "error",
          message: "Please provide a valid approved amount greater than zero.",
        });
      }

      // 3. Validate the currency.
      const allowedCurrencies = ["INR", "USD", "EUR", "GBP"];

      if (!allowedCurrencies.includes(currency)) {
        return res.status(400).json({
          status: "error",
          message: "Unsupported currency.",
        });
      }

      // Razorpay integration in this workflow initially uses INR.
      if (currency !== "INR") {
        return res.status(400).json({
          status: "error",
          message: "Promotion payments currently support INR only.",
        });
      }

      // 4. Find the promotion.
      const advertisement = await Advertisement.findById(id);

      if (!advertisement) {
        return res.status(404).json({
          status: "error",
          message: "Promotion not found.",
        });
      }

      // 5. Do not approve completed promotions.
      if (advertisement.status === "completed") {
        return res.status(400).json({
          status: "error",
          message: "Completed promotions cannot be approved.",
        });
      }

      // 6. Do not approve rejected promotions without
      // an explicit re-submission/review workflow.
      if (advertisement.status === "rejected") {
        return res.status(400).json({
          status: "error",
          message:
            "This promotion was rejected. It must be resubmitted before approval.",
        });
      }

      // 7. Do not change the amount after payment.
      if (advertisement.payment_status === "paid") {
        return res.status(409).json({
          status: "error",
          message:
            "This promotion has already been paid for. The approved amount cannot be changed.",
        });
      }

      // 8. Record approval and amount.
      advertisement.status = "approved";
      advertisement.approved_amount = amount;
      advertisement.currency = "INR";
      advertisement.rejection_reason = "";
      advertisement.reviewed_at = new Date();

      // Use the authenticated administrator's ID.
      advertisement.reviewed_by = req.admin.id;

      // Approval alone must never activate the campaign.
      advertisement.is_active = false;

      // If an unpaid promotion's amount changes, an old
      // payment link must not remain usable by this workflow.
      // Payment-link generation will create a fresh link.
      advertisement.payment_link_id = "";
      advertisement.payment_link_url = "";
      advertisement.payment_link_sent_at = null;
      advertisement.payment_reference = "";
      advertisement.payment_paid_at = null;
      advertisement.payment_status = "pending";

      await advertisement.save();

      return res.status(200).json({
        status: "success",
        message:
          "Promotion approved and amount recorded. Generate a payment link for the owner next.",
        advertisement,
      });
    } catch (error) {
      console.error("Approve promotion error:", error);

      // Handle schema validation errors.
      if (error.name === "ValidationError") {
        return res.status(400).json({
          status: "error",
          message: error.message,
        });
      }

      return res.status(500).json({
        status: "error",
        message: "Failed to approve promotion.",
      });
    }
  }
);

/* ============================================
   ADMIN: GENERATE RAZORPAY PAYMENT LINK
   POST /admin/advertisements/:id/payment-link

   Requires:
   - Approved promotion
   - Valid approved amount
   - Owner contact email
============================================ */

app.post(
  "/admin/advertisements/:id/payment-link",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // 1. Validate promotion ID.
      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid promotion ID.",
        });
      }

      // 2. Verify Razorpay configuration.
      if (
        !process.env.RAZORPAY_KEY_ID ||
        !process.env.RAZORPAY_KEY_SECRET
      ) {
        return res.status(500).json({
          status: "error",
          message: "Razorpay is not configured on the server.",
        });
      }

      // 3. Find promotion.
      const advertisement = await Advertisement.findById(id);

      if (!advertisement) {
        return res.status(404).json({
          status: "error",
          message: "Promotion not found.",
        });
      }

      // 4. Promotion must be approved.
      if (advertisement.status !== "approved") {
        return res.status(400).json({
          status: "error",
          message:
            "Only approved promotions can receive payment links.",
        });
      }

      // 5. Validate approved amount.
      const amount = Number(advertisement.approved_amount);

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "The promotion does not have a valid GM-approved amount.",
        });
      }

      // 6. This integration initially supports INR only.
      if (advertisement.currency !== "INR") {
        return res.status(400).json({
          status: "error",
          message:
            "Razorpay payment links in this workflow support INR only.",
        });
      }

      // 7. Validate owner email.
      const email = String(
        advertisement.contact_email || ""
      ).trim();

      const validEmail =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      if (!validEmail) {
        return res.status(400).json({
          status: "error",
          message:
            "The promotion does not have a valid owner contact email.",
        });
      }

      // 8. Don't generate another link after payment.
      if (advertisement.payment_status === "paid") {
        return res.status(409).json({
          status: "error",
          message:
            "Payment has already been received for this promotion.",
        });
      }

      // 9. Don't create duplicate links on repeated requests.
      if (
        advertisement.payment_link_id &&
        advertisement.payment_link_url &&
        advertisement.payment_status === "pending"
      ) {
        return res.status(409).json({
          status: "error",
          message:
            "A payment link already exists. Use the existing link or invalidate it through Razorpay before generating a replacement.",
          payment_link_url:
            advertisement.payment_link_url,
          payment_link_id:
            advertisement.payment_link_id,
        });
      }

      // 10. Create the Razorpay Payment Link.
      // Razorpay expects the amount in the smallest currency unit.
      // For INR, 5000 rupees = 500000 paise.
      const amountInPaise = Math.round(amount * 100);

      if (
        !Number.isSafeInteger(amountInPaise) ||
        amountInPaise <= 0
      ) {
        return res.status(400).json({
          status: "error",
          message: "The approved amount is invalid.",
        });
      }

      const paymentLink = await razorpay.paymentLink.create({
        amount: amountInPaise,
        currency: "INR",

        accept_partial: false,

        description:
          `DWJD promotion payment - ${
            advertisement.brand_name || advertisement.title
          }`,

        customer: {
          name:
            advertisement.contact_person ||
            advertisement.brand_name ||
            "Promotion Owner",
          email,
          contact:
            advertisement.contact_phone
              ? String(advertisement.contact_phone)
              : undefined,
        },

        reference_id: `ad_${advertisement._id}`,

        notes: {
          advertisement_id: String(advertisement._id),
          brand_name: String(
            advertisement.brand_name || ""
          ).slice(0, 256),
        },

        reminder_enable: true,
      });

      // 11. Save payment details before sending email.
      advertisement.payment_link_id = paymentLink.id;
      advertisement.payment_link_url =
        paymentLink.short_url;
      advertisement.payment_link_sent_at = new Date();
      advertisement.payment_status = "pending";
      advertisement.is_active = false;

      await advertisement.save();

      // 12. Escape dynamic values used in the HTML email.
      const escapeHtml = (value) =>
        String(value ?? "").replace(
          /[&<>"']/g,
          (character) =>
            ({
              "&": "&amp;",
              "<": "&lt;",
              ">": "&gt;",
              '"': "&quot;",
              "'": "&#39;",
            })[character]
        );

      const brandName = escapeHtml(
        advertisement.brand_name ||
        advertisement.title ||
        "your promotion"
      );

      const ownerName = escapeHtml(
        advertisement.contact_person ||
        "Promotion Owner"
      );

      const paymentUrl = escapeHtml(
        paymentLink.short_url
      );

      // 13. Send payment link using your existing Brevo helper.
      try {
        await sendEmail({
          to: email,
          subject: "DWJD promotion — payment required",

          html: `
            <div style="
              font-family: Arial, sans-serif;
              max-width: 600px;
              margin: auto;
              padding: 24px;
              color: #222;
            ">
              <h2>DWJD — Promotion Payment</h2>

              <p>Hello ${ownerName},</p>

              <p>
                Your promotion for
                <strong>${brandName}</strong>
                has been approved.
              </p>

              <p>
                <strong>Approved amount:</strong>
                ₹${amount.toFixed(2)}
              </p>

              <p>
                Please use the secure Razorpay payment link below
                to complete your payment.
              </p>

              <p style="margin: 28px 0;">
                <a
                  href="${paymentUrl}"
                  style="
                    background: #146c43;
                    color: #fff;
                    padding: 14px 24px;
                    border-radius: 6px;
                    text-decoration: none;
                    display: inline-block;
                    font-weight: bold;
                  "
                >
                  Pay Now
                </a>
              </p>

              <p>
                Your promotion will not become active until
                the payment is verified and the campaign is
                eligible for activation.
              </p>

              <p>
                Thank you,<br />
                DWJD Team
              </p>
            </div>
          `,
        });
      } catch (emailError) {
        console.error(
          "Payment link email failed:",
          emailError.message
        );

        // The Razorpay link was already created and saved.
        // Return it so the administrator can retry delivery
        // using a dedicated email-retry API later.
        return res.status(502).json({
          status: "partial_success",
          message:
            "Payment link was created and saved, but the email could not be sent. Do not generate another link; retry email delivery using the existing link.",
          payment_link_id: paymentLink.id,
          payment_link_url: paymentLink.short_url,
          email_sent: false,
          advertisement_id: String(advertisement._id),
        });
      }

      // 14. Success response.
      return res.status(201).json({
        status: "success",
        message:
          "Razorpay payment link created and emailed to the promotion owner.",

        email_sent: true,

        payment: {
          payment_link_id: paymentLink.id,
          payment_link_url: paymentLink.short_url,
          amount,
          currency: "INR",
          status: paymentLink.status,
        },

        advertisement_id: String(advertisement._id),
      });
    } catch (error) {
      console.error(
        "Generate Razorpay payment link error:",
        error
      );

      return res.status(500).json({
        status: "error",
        message:
          "Failed to generate the Razorpay payment link.",
      });
    }
  }
);

// ============================================
// API 4: RAZORPAY PAYMENT WEBHOOK
// ============================================

app.post("/webhooks/razorpay", async (req, res) => {
  try {
    // 1. Check webhook configuration
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error("RAZORPAY_WEBHOOK_SECRET is not configured.");

      return res.status(500).json({
        success: false,
        message: "Webhook configuration error.",
      });
    }

    // 2. Ensure the original request body is available
    if (!req.rawBody || !Buffer.isBuffer(req.rawBody)) {
      return res.status(400).json({
        success: false,
        message: "Raw webhook body is missing.",
      });
    }

    // 3. Read Razorpay's signature header
    const receivedSignature = req.headers["x-razorpay-signature"];

    if (
      typeof receivedSignature !== "string" ||
      !/^[a-f0-9]{64}$/i.test(receivedSignature)
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid webhook signature.",
      });
    }

    // 4. Calculate the expected HMAC signature
    const expectedSignature = crypto
      .createHmac("sha256", webhookSecret)
      .update(req.rawBody)
      .digest();

    const receivedSignatureBuffer = Buffer.from(
      receivedSignature,
      "hex"
    );

    // 5. Compare signatures securely
    if (
      expectedSignature.length !== receivedSignatureBuffer.length ||
      !crypto.timingSafeEqual(
        expectedSignature,
        receivedSignatureBuffer
      )
    ) {
      console.warn("Razorpay webhook signature verification failed.");

      return res.status(401).json({
        success: false,
        message: "Webhook signature verification failed.",
      });
    }

    // 6. Read the verified event
    const event = req.body?.event;

    // We process payment_link.paid only.
    // Other valid Razorpay events can safely be acknowledged.
    if (event !== "payment_link.paid") {
      return res.status(200).json({
        success: true,
        message: "Webhook received; event ignored.",
      });
    }

    // 7. Extract the payment-link and payment details
    const paymentLink =
      req.body?.payload?.payment_link?.entity;

    const payment =
      req.body?.payload?.payment?.entity;

    if (!paymentLink || !payment) {
      return res.status(400).json({
        success: false,
        message: "Payment-link or payment details are missing.",
      });
    }

    const paymentLinkId = paymentLink.id;
    const paymentId = payment.id;

    if (!paymentLinkId || !paymentId) {
      return res.status(400).json({
        success: false,
        message: "Payment identifiers are missing.",
      });
    }

    // 8. Locate the promotion using its stored payment-link ID
    const advertisement = await Advertisement.findOne({
      payment_link_id: paymentLinkId,
    });

    if (!advertisement) {
      console.error(
        "No promotion found for Razorpay payment link:",
        paymentLinkId
      );

      // Acknowledge the event to avoid endless retries.
      // Investigate this mismatch using your server logs.
      return res.status(200).json({
        success: true,
        message: "No matching promotion found; event recorded for investigation.",
      });
    }

    // 9. Confirm the payment link refers to this promotion
    const expectedReferenceId = `ad_${advertisement._id}`;

    if (paymentLink.reference_id !== expectedReferenceId) {
      console.error(
        "Payment-link reference mismatch:",
        paymentLinkId
      );

      return res.status(400).json({
        success: false,
        message: "Payment-link reference mismatch.",
      });
    }

    // 10. Confirm the payment details
    const expectedAmountPaise = Math.round(
      Number(advertisement.approved_amount) * 100
    );

    const validAmount =
      Number.isSafeInteger(expectedAmountPaise) &&
      Number(paymentLink.amount) === expectedAmountPaise &&
      Number(payment.amount) === expectedAmountPaise;

    const validCurrency =
      advertisement.currency === "INR" &&
      paymentLink.currency === "INR" &&
      payment.currency === "INR";

    const validPaymentStatus = payment.status === "captured";

    const validLinkStatus = paymentLink.status === "paid";

    if (
      !validAmount ||
      !validCurrency ||
      !validPaymentStatus ||
      !validLinkStatus
    ) {
      console.error("Razorpay payment validation failed:", {
        paymentLinkId,
        paymentId,
        validAmount,
        validCurrency,
        validPaymentStatus,
        validLinkStatus,
      });

      return res.status(400).json({
        success: false,
        message: "Payment validation failed.",
      });
    }

    // 11. Ensure the payment link belongs to the approved amount
    if (
      advertisement.status !== "approved" ||
      !advertisement.approved_amount ||
      Number(advertisement.approved_amount) <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Promotion is not eligible for payment confirmation.",
      });
    }

    // 12. Handle duplicate webhook deliveries idempotently
    if (advertisement.payment_status === "paid") {
      if (advertisement.payment_reference === paymentId) {
        return res.status(200).json({
          success: true,
          message: "Payment was already recorded.",
        });
      }

      console.error(
        "Different payment received for an already-paid promotion:",
        {
          advertisementId: String(advertisement._id),
          existingPaymentId: advertisement.payment_reference,
          incomingPaymentId: paymentId,
        }
      );

      return res.status(409).json({
        success: false,
        message: "Promotion is already marked as paid.",
      });
    }

    // 13. Update payment information
    advertisement.payment_status = "paid";
    advertisement.payment_reference = paymentId;

    advertisement.payment_paid_at = payment.created_at
      ? new Date(payment.created_at * 1000)
      : new Date();

    // Payment does not automatically activate the promotion.
    advertisement.is_active = false;

    await advertisement.save();

    // 14. Respond successfully to Razorpay
    console.log("Promotion payment verified successfully:", {
      advertisementId: String(advertisement._id),
      paymentLinkId,
      paymentId,
    });

    return res.status(200).json({
      success: true,
      message: "Payment verified and recorded successfully.",
      advertisement_id: String(advertisement._id),
      payment_status: advertisement.payment_status,
    });
  } catch (error) {
    console.error(
      "Razorpay webhook processing error:",
      error.response?.data || error.message
    );

    return res.status(500).json({
      success: false,
      message: "Webhook processing failed.",
    });
  }
});
// ============================================
// API 4: RAZORPAY PAYMENT WEBHOOK
// ============================================

app.post("/webhooks/razorpay", async (req, res) => {
  try {
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error("RAZORPAY_WEBHOOK_SECRET is missing");

      return res.status(500).json({
        success: false,
        message: "Webhook configuration error",
      });
    }

    // Verify the original request body exists
    if (!Buffer.isBuffer(req.rawBody)) {
      return res.status(400).json({
        success: false,
        message: "Raw request body is missing",
      });
    }

    // Read Razorpay signature
    const signature = req.headers["x-razorpay-signature"];

    if (
      typeof signature !== "string" ||
      !/^[a-f0-9]{64}$/i.test(signature)
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid webhook signature",
      });
    }

    // Generate expected signature
    const expectedSignature = crypto
      .createHmac("sha256", webhookSecret)
      .update(req.rawBody)
      .digest();

    const receivedSignature = Buffer.from(signature, "hex");

    // Compare signatures safely
    if (
      expectedSignature.length !== receivedSignature.length ||
      !crypto.timingSafeEqual(
        expectedSignature,
        receivedSignature
      )
    ) {
      return res.status(401).json({
        success: false,
        message: "Webhook signature verification failed",
      });
    }

    // Only process payment_link.paid
    const event = req.body?.event;

    if (event !== "payment_link.paid") {
      return res.status(200).json({
        success: true,
        message: "Event acknowledged",
      });
    }

    // Extract Razorpay entities
    const paymentLink =
      req.body?.payload?.payment_link?.entity;

    const payment =
      req.body?.payload?.payment?.entity;

    if (!paymentLink || !payment) {
      return res.status(400).json({
        success: false,
        message: "Payment information is missing",
      });
    }

    if (!paymentLink.id || !payment.id) {
      return res.status(400).json({
        success: false,
        message: "Payment identifiers are missing",
      });
    }

    // Find the promotion associated with this payment link
    const advertisement = await Advertisement.findOne({
      payment_link_id: paymentLink.id,
    });

    if (!advertisement) {
      console.error(
        "No promotion found for payment link:",
        paymentLink.id
      );

      return res.status(200).json({
        success: true,
        message: "No matching promotion found",
      });
    }

    // Validate the payment-link reference
    const expectedReference = `ad_${advertisement._id}`;

    if (paymentLink.reference_id !== expectedReference) {
      return res.status(400).json({
        success: false,
        message: "Payment reference mismatch",
      });
    }

    // Validate the expected amount
    const expectedAmount = Math.round(
      Number(advertisement.approved_amount) * 100
    );

    const validAmount =
      Number.isSafeInteger(expectedAmount) &&
      Number(paymentLink.amount) === expectedAmount &&
      Number(payment.amount) === expectedAmount;

    // Validate currency and statuses
    const validCurrency =
      advertisement.currency === "INR" &&
      paymentLink.currency === "INR" &&
      payment.currency === "INR";

    const validPayment =
      payment.status === "captured" &&
      paymentLink.status === "paid";

    if (!validAmount || !validCurrency || !validPayment) {
      console.error("Razorpay payment validation failed", {
        paymentLinkId: paymentLink.id,
        paymentId: payment.id,
        validAmount,
        validCurrency,
        validPayment,
      });

      return res.status(400).json({
        success: false,
        message: "Payment validation failed",
      });
    }

    // Ensure the promotion was approved
    if (
      advertisement.status !== "approved" ||
      Number(advertisement.approved_amount) <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Promotion is not eligible for payment confirmation",
      });
    }

    // Idempotency: accept a duplicate delivery of the same payment
    if (advertisement.payment_status === "paid") {
      if (advertisement.payment_reference === payment.id) {
        return res.status(200).json({
          success: true,
          message: "Payment already recorded",
        });
      }

      return res.status(409).json({
        success: false,
        message: "Promotion is already marked as paid",
      });
    }

    // Record verified payment
    advertisement.payment_status = "paid";
    advertisement.payment_reference = payment.id;

    advertisement.payment_paid_at = payment.created_at
      ? new Date(payment.created_at * 1000)
      : new Date();

    // Payment alone must not activate the promotion
    advertisement.is_active = false;

    await advertisement.save();

    console.log("Promotion payment verified:", {
      advertisementId: String(advertisement._id),
      paymentLinkId: paymentLink.id,
      paymentId: payment.id,
    });

    return res.status(200).json({
      success: true,
      message: "Payment verified successfully",
      advertisement_id: String(advertisement._id),
      payment_status: "paid",
    });
  } catch (error) {
    console.error(
      "Razorpay webhook error:",
      error.response?.data || error.message
    );

    return res.status(500).json({
      success: false,
      message: "Webhook processing failed",
    });
  }
});
// ============================================
// API 5: ACTIVATE PROMOTION
// ============================================

app.patch(
  "/admin/advertisements/:id/activate",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // 1. Validate advertisement ID
      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid advertisement ID.",
        });
      }

      // 2. Find the advertisement
      const advertisement = await Advertisement.findById(id);

      if (!advertisement) {
        return res.status(404).json({
          success: false,
          message: "Promotion not found.",
        });
      }

      // 3. Ensure the promotion has been approved
      if (advertisement.status !== "approved") {
        return res.status(400).json({
          success: false,
          message: "Only approved promotions can be activated.",
        });
      }

      // 4. Ensure payment is completed
      if (advertisement.payment_status !== "paid") {
        return res.status(400).json({
          success: false,
          message: "Payment has not been completed.",
        });
      }

      // 5. Ensure the approved amount is valid
      if (
        !Number.isFinite(Number(advertisement.approved_amount)) ||
        Number(advertisement.approved_amount) <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "The approved promotion amount is invalid.",
        });
      }

      // 6. Validate campaign dates
      const now = new Date();
      const startDate = new Date(advertisement.start_date);
      const endDate = new Date(advertisement.end_date);

      if (
        !advertisement.start_date ||
        !advertisement.end_date ||
        Number.isNaN(startDate.getTime()) ||
        Number.isNaN(endDate.getTime())
      ) {
        return res.status(400).json({
          success: false,
          message: "Campaign start date or end date is invalid.",
        });
      }

      if (endDate < startDate) {
        return res.status(400).json({
          success: false,
          message: "Campaign end date cannot precede the start date.",
        });
      }

      if (now < startDate) {
        return res.status(400).json({
          success: false,
          message: "The campaign has not started yet.",
          campaign_start_date: startDate,
        });
      }

      if (now > endDate) {
        return res.status(400).json({
          success: false,
          message: "The campaign has already ended.",
          campaign_end_date: endDate,
        });
      }

      // 7. Prevent unnecessary repeated activation
      if (advertisement.is_active === true) {
        return res.status(200).json({
          success: true,
          message: "Promotion is already active.",
          advertisement_id: String(advertisement._id),
          is_active: true,
        });
      }

      // 8. Activate the promotion
      advertisement.is_active = true;

      await advertisement.save();

      // 9. Send response
      return res.status(200).json({
        success: true,
        message: "Promotion activated successfully.",
        advertisement: {
          id: String(advertisement._id),
          title: advertisement.title,
          brand_name: advertisement.brand_name,
          status: advertisement.status,
          payment_status: advertisement.payment_status,
          is_active: advertisement.is_active,
          start_date: advertisement.start_date,
          end_date: advertisement.end_date,
        },
      });
    } catch (error) {
      console.error("Activate promotion error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Failed to activate promotion.",
      });
    }
  }
);

/* ============================================
   REJECT PROMOTION
   PATCH /admin/advertisements/:id/reject
============================================ */

app.patch(
  "/admin/advertisements/:id/reject",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { rejection_reason } = req.body;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid promotion ID.",
        });
      }

      if (
        typeof rejection_reason !== "string" ||
        rejection_reason.trim().length < 5
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Please provide a rejection reason of at least 5 characters.",
        });
      }

      const advertisement = await Advertisement.findById(id);

      if (!advertisement) {
        return res.status(404).json({
          status: "error",
          message: "Promotion not found.",
        });
      }

      if (advertisement.status === "completed") {
        return res.status(400).json({
          status: "error",
          message: "Completed promotions cannot be rejected.",
        });
      }

      advertisement.status = "rejected";
      advertisement.rejection_reason = rejection_reason.trim();
      advertisement.reviewed_at = new Date();
      advertisement.reviewed_by = req.admin.id;

      // A rejected promotion must never remain active.
      advertisement.is_active = false;

      await advertisement.save();

      return res.status(200).json({
        status: "success",
        message: "Promotion rejected successfully.",
        advertisement,
      });
    } catch (error) {
      console.error("Reject promotion error:", error);

      return res.status(500).json({
        status: "error",
        message: "Failed to reject promotion.",
      });
    }
  }
);
app.patch(
  "/admin/advertisements/:id/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const advertisement = await Advertisement.findById(id);

      if (!advertisement) {
        return res.status(404).json({
          success: false,
          message: "Promotion not found.",
        });
      }

      if (advertisement.status === "completed") {
        return res.status(400).json({
          success: false,
          message: "Completed promotions cannot be approved again.",
        });
      }

      advertisement.status = "approved";
      advertisement.rejection_reason = "";
      advertisement.reviewed_at = new Date();

      // Do not activate automatically.
      // Activation also requires verified payment.
      advertisement.is_active = false;

      // Set reviewed_by here using the authenticated admin's
      // actual database ID, according to your authentication setup.

      await advertisement.save();

      return res.status(200).json({
        success: true,
        message: "Promotion approved successfully.",
        advertisement,
      });
    } catch (error) {
      console.error("Approve promotion error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to approve promotion.",
      });
    }
  }
);
// ==========================================
// ADMIN: APPROVE ADVERTISEMENT
// ==========================================

app.patch(
  "/admin/advertisements/:id/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid promotion ID.",
        });
      }

      const advertisement = await Advertisement.findById(id);

      if (!advertisement) {
        return res.status(404).json({
          status: "error",
          message: "Promotion not found in the database.",
        });
      }

      if (advertisement.status === "completed") {
        return res.status(400).json({
          status: "error",
          message: "Completed promotions cannot be approved.",
        });
      }

      advertisement.status = "approved";
      advertisement.rejection_reason = "";
      advertisement.reviewed_at = new Date();
      advertisement.is_active = false;

      await advertisement.save();

      return res.status(200).json({
        status: "success",
        message: "Promotion approved successfully.",
        advertisement,
      });
    } catch (error) {
      console.error("Approve advertisement error:", error);

      return res.status(500).json({
        status: "error",
        message: "Failed to approve advertisement.",
      });
    }
  }
);
app.patch(
  "/admin/advertisements/:id/reject",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { rejection_reason } = req.body;

      if (
        typeof rejection_reason !== "string" ||
        rejection_reason.trim().length < 5
      ) {
        return res.status(400).json({
          success: false,
          message: "Please provide a rejection reason of at least 5 characters.",
        });
      }

      const advertisement = await Advertisement.findById(id);

      if (!advertisement) {
        return res.status(404).json({
          success: false,
          message: "Promotion not found.",
        });
      }

      if (advertisement.status === "completed") {
        return res.status(400).json({
          success: false,
          message: "Completed promotions cannot be rejected.",
        });
      }

      advertisement.status = "rejected";
      advertisement.rejection_reason = rejection_reason.trim();
      advertisement.reviewed_at = new Date();
      advertisement.is_active = false;

      await advertisement.save();

      return res.status(200).json({
        success: true,
        message: "Promotion rejected successfully.",
        advertisement,
      });
    } catch (error) {
      console.error("Reject promotion error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to reject promotion.",
      });
    }
  }
);
// ============================================
// API 6: DEACTIVATE EXPIRED PROMOTIONS
// ============================================

const deactivateExpiredPromotions = async () => {
  try {
    const now = new Date();

    const result = await Advertisement.updateMany(
      {
        is_active: true,
        end_date: { $lt: now },
      },
      {
        $set: {
          is_active: false,
        },
      }
    );

    if (result.modifiedCount > 0) {
      console.log(
        `Deactivated ${result.modifiedCount} expired promotion(s).`
      );
    }

    return result.modifiedCount || 0;
  } catch (error) {
    console.error(
      "Failed to deactivate expired promotions:",
      error.message
    );

    throw error;
  }
};
// ============================================
// MANUAL ADMIN API: DEACTIVATE EXPIRED PROMOTIONS
// ============================================

app.patch(
  "/admin/advertisements/deactivate-expired",
  requireAdmin,
  async (req, res) => {
    try {
      const deactivatedCount = await deactivateExpiredPromotions();

      return res.status(200).json({
        success: true,
        message: "Expired promotions checked successfully.",
        deactivated_count: deactivatedCount,
      });
    } catch (error) {
      console.error("Admin expiration cleanup failed:", error.message);

      return res.status(500).json({
        success: false,
        message: "Failed to deactivate expired promotions.",
      });
    }
  }
);
// ============================================
// AUTOMATIC PROMOTION EXPIRATION SCHEDULER
// Runs every 5 minutes
// ============================================

cron.schedule("*/5 * * * *", async () => {
  try {
    await deactivateExpiredPromotions();
  } catch (error) {
    console.error(
      "Scheduled promotion cleanup failed:",
      error.message
    );
  }
});
// ============================================
// API 7: GET PUBLIC ACTIVE PROMOTIONS
// ============================================

app.get("/advertisements/active", async (req, res) => {
  try {
    const now = new Date();

    const advertisements = await Advertisement.find({
      status: "approved",
      payment_status: "paid",
      is_active: true,

      start_date: { $lte: now },
      end_date: { $gte: now },
    })
      .select(
        [
          "title",
          "brand_name",
          "description",
          "image_url",
          "video_url",
          "collaboration_type",
          "start_date",
          "end_date",
          "status",
          "is_active",
        ].join(" ")
      )
      .sort({ createdAt: -1 })
      .lean();

    return res.status(200).json({
      success: true,
      count: advertisements.length,
      advertisements,
    });
  } catch (error) {
    console.error("Fetch public promotions error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch active promotions.",
    });
  }
});
// ============================================
// API 8: GET SINGLE ACTIVE PROMOTION BY ID
// ============================================

app.get("/advertisements/active/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // 1. Validate the MongoDB ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid advertisement ID.",
      });
    }

    // 2. Get the current time
    const now = new Date();

    // 3. Fetch only a publicly eligible promotion
    const advertisement = await Advertisement.findOne({
      _id: id,
      status: "approved",
      payment_status: "paid",
      is_active: true,
      start_date: { $lte: now },
      end_date: { $gte: now },
    })
      .select(
        [
          "title",
          "brand_name",
          "description",
          "image_url",
          "video_url",
          "collaboration_type",
          "start_date",
          "end_date",
          "status",
          "is_active",
        ].join(" ")
      )
      .lean();

    // 4. Return 404 if the promotion isn't publicly available
    if (!advertisement) {
      return res.status(404).json({
        success: false,
        message: "Promotion not found or is not currently available.",
      });
    }

    // 5. Return the promotion details
    return res.status(200).json({
      success: true,
      advertisement,
    });
  } catch (error) {
    console.error(
      "Fetch promotion details error:",
      error.message
    );

    return res.status(500).json({
      success: false,
      message: "Failed to fetch promotion details.",
    });
  }
});
/*
DWJD PROMOTION-SPECIFIC RAZORPAY QR ROUTE
Paste this into Mongod.js AFTER:
  const razorpay = new Razorpay({ key_id: ..., key_secret: ... });

It relies on the existing requireAdmin middleware, Advertisement model,
mongoose, and razorpay instance. Do not create another webhook route.
*/

app.post("/admin/advertisements/:id/qr-code", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ status: "error", message: "Invalid promotion ID." });
    }

    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
      return res.status(503).json({ status: "error", message: "Razorpay API credentials are not configured." });
    }

    const ad = await Advertisement.findById(id);
    if (!ad) {
      return res.status(404).json({ status: "error", message: "Promotion not found." });
    }

    if (ad.status !== "approved") {
      return res.status(409).json({ status: "error", message: "Only GM-approved promotions can receive a QR code." });
    }

    if (ad.payment_status === "paid") {
      return res.status(409).json({ status: "error", message: "This promotion is already paid." });
    }

    const amount = Number(ad.approved_amount);
    if (!Number.isFinite(amount) || amount <= 0 || ad.currency !== "INR") {
      return res.status(400).json({ status: "error", message: "A valid GM-approved INR amount is required." });
    }

    const amountInPaise = Math.round(amount * 100);
    if (!Number.isSafeInteger(amountInPaise) || amountInPaise < 100) {
      return res.status(400).json({ status: "error", message: "QR payments must be at least ₹1.00 and use a valid amount." });
    }

    // Prevent a second active payment route for the same campaign.
    // Close/invalidate an old payment link in Razorpay before creating a QR.
    if (ad.payment_link_id && ad.payment_link_url) {
      return res.status(409).json({
        status: "error",
        message: "A payment link already exists for this promotion. Close/invalidate it in Razorpay before creating a QR to avoid duplicate payment routes.",
        payment_link_url: ad.payment_link_url,
      });
    }

    // Return existing QR instead of creating duplicates on repeat clicks.
    if (ad.qr_code_id && ad.qr_code_image_url && ["created", "active"].includes(ad.qr_code_status)) {
      return res.status(200).json({
        status: "success",
        message: "A QR code already exists for this promotion.",
        qr_code: {
          id: ad.qr_code_id,
          image_url: ad.qr_code_image_url,
          status: ad.qr_code_status,
          amount: ad.approved_amount,
          currency: ad.currency,
        },
      });
    }

    const name = `DWJD ${ad.brand_name || ad.title}`.replace(/\s+/g, " ").slice(0, 40);
    const qr = await razorpay.qrCode.create({
      type: "upi_qr",
      name,
      usage: "single_use",
      fixed_amount: true,
      payment_amount: amountInPaise,
      description: `DWJD promotion - ${String(ad.brand_name || ad.title).slice(0, 100)}`,
      notes: {
        advertisement_id: String(ad._id),
        brand_name: String(ad.brand_name || "").slice(0, 100),
      },
    });

    if (!qr?.id || !qr?.image_url) {
      console.error("Razorpay QR response missing ID or image URL:", qr);
      return res.status(502).json({ status: "error", message: "Razorpay did not return a usable QR code." });
    }

    ad.qr_code_id = qr.id;
    ad.qr_code_image_url = qr.image_url;
    ad.qr_code_status = qr.status === "active" ? "active" : "created";
    ad.qr_code_created_at = qr.created_at ? new Date(qr.created_at * 1000) : new Date();
    await ad.save();

    return res.status(201).json({
      status: "success",
      message: "Promotion-specific QR code created.",
      qr_code: {
        id: ad.qr_code_id,
        image_url: ad.qr_code_image_url,
        status: ad.qr_code_status,
        amount: ad.approved_amount,
        currency: ad.currency,
        promotion_id: String(ad._id),
        brand_name: ad.brand_name,
      },
    });
  } catch (error) {
    console.error("Create promotion QR error:", error.response?.data || error.message);
    return res.status(500).json({
      status: "error",
      message: error.response?.data?.error?.description || "Failed to create promotion QR code.",
    });
  }
});

/*
WEBHOOK PATCH:
Inside the FIRST existing app.post("/webhooks/razorpay", ...) handler,
after its HMAC signature has been verified and after `const event = req.body?.event;`,
insert this branch BEFORE the current:
  if (event !== "payment_link.paid") { ... }

Do not add a second app.post("/webhooks/razorpay") route.
*/
async function processPromotionQrCreditedWebhook(req, res) {
  const qr = req.body?.payload?.qr_code?.entity;
  const payment = req.body?.payload?.payment?.entity;

  if (!qr?.id || !payment?.id) {
    return res.status(400).json({ success: false, message: "QR code or payment details are missing." });
  }

  const ad = await Advertisement.findOne({ qr_code_id: qr.id });
  if (!ad) {
    // Acknowledge unmatched events to avoid endless retries; investigate server logs.
    console.error("QR webhook has no matching promotion:", { qrCodeId: qr.id, paymentId: payment.id });
    return res.status(200).json({ success: true, message: "No matching promotion found; event logged." });
  }

  const expectedAmountPaise = Math.round(Number(ad.approved_amount) * 100);
  const validAmount = Number.isSafeInteger(expectedAmountPaise) &&
    Number(payment.amount) === expectedAmountPaise;
  const validCurrency = ad.currency === "INR" && payment.currency === "INR";
  const validStatus = payment.status === "captured" && payment.captured === true;

  if (!validAmount || !validCurrency || !validStatus) {
    console.error("QR payment validation failed:", {
      advertisementId: String(ad._id),
      qrCodeId: qr.id,
      paymentId: payment.id,
      validAmount,
      validCurrency,
      validStatus,
    });
    return res.status(400).json({ success: false, message: "QR payment validation failed." });
  }

  if (ad.status !== "approved" || !Number.isFinite(Number(ad.approved_amount)) || Number(ad.approved_amount) <= 0) {
    return res.status(400).json({ success: false, message: "Promotion is not eligible for payment confirmation." });
  }

  // Idempotency: Razorpay may retry webhook delivery.
  if (ad.payment_status === "paid") {
    if (ad.payment_reference === payment.id || ad.qr_payment_reference === payment.id) {
      return res.status(200).json({ success: true, message: "QR payment was already recorded." });
    }
    console.error("Another payment arrived for an already-paid promotion:", {
      advertisementId: String(ad._id),
      existingPaymentId: ad.payment_reference,
      incomingPaymentId: payment.id,
    });
    return res.status(409).json({ success: false, message: "Promotion is already marked as paid." });
  }

  // Avoid overwriting a different successful payment from the payment-link workflow.
  if (ad.payment_reference && ad.payment_reference !== payment.id) {
    return res.status(409).json({ success: false, message: "A different payment reference is already recorded." });
  }

  ad.payment_status = "paid";
  ad.payment_reference = payment.id;
  ad.qr_payment_reference = payment.id;
  ad.payment_paid_at = payment.created_at ? new Date(payment.created_at * 1000) : new Date();
  ad.qr_payment_paid_at = ad.payment_paid_at;
  ad.qr_code_status = qr.status === "closed" ? "closed" : (ad.qr_code_status || "active");
  // Payment confirmation must not auto-activate a campaign.
  ad.is_active = false;

  await ad.save();

  console.log("Promotion QR payment verified:", {
    advertisementId: String(ad._id),
    qrCodeId: qr.id,
    paymentId: payment.id,
    amount: ad.approved_amount,
  });

  return res.status(200).json({
    success: true,
    message: "QR payment verified and recorded.",
    advertisement_id: String(ad._id),
    payment_status: ad.payment_status,
  });
}

/*
Insert inside the existing webhook handler after signature verification:
if (event === "qr_code.credited") {
  return await processPromotionQrCreditedWebhook(req, res);
}
Then leave the existing payment_link.paid processing intact.
*/

/* ================= SERVER START ================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));