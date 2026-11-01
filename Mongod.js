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

/* =========================================================
   CORS & REQUEST PARSING MIDDLEWARE
========================================================= */

const allowedOrigins = [
  "https://dwjd.vercel.app",
  "http://localhost:5173",
  "https://dwjd-org.vercel.app",
  "http://192.168.1.12:5173",
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

/* =========================================================
   DATABASE CONNECTION
========================================================= */

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

/* =========================================================
   GOOGLE DRIVE CONFIGURATION
========================================================= */

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

/* =========================================================
   RAZORPAY CONFIGURATION
========================================================= */

if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.warn("⚠️ Razorpay configuration is missing.");
}

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "",
});

/* =========================================================
   HELPERS & EMAIL SERVICE
========================================================= */

const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

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

const sendOTP = async (email, otp) => {
  await sendEmail({
    to: email,
    subject: "DWJD Verification Code",
    html: `
      <h2>DWJD Verification</h2>
      <h1>${otp}</h1>
      <p>Valid for 10 minutes</p>
    `,
  });
};

/* =========================================================
   AUTHENTICATION & AUTHORIZATION MIDDLEWARES
========================================================= */

// 1. General User Authentication
const requireUser = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).json({ status: "unauthorized", message: "Please log in to continue." });
    }
    const token = authorization.slice(7).trim();
    if (!token) {
      return res.status(401).json({ status: "unauthorized", message: "Authentication token missing." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.id) {
      return res.status(401).json({ status: "unauthorized", message: "Invalid session." });
    }

    const user = await User.findById(decoded.id).select("-password -otp -otp_expiry").lean();
    if (!user) {
      return res.status(401).json({ status: "unauthorized", message: "User account not found." });
    }
    if (!user.is_active) {
      return res.status(403).json({ status: "forbidden", message: "Account is inactive." });
    }

    req.user = user;
    return next();
  } catch (error) {
    return res.status(401).json({ status: "unauthorized", message: "Session expired or invalid." });
  }
};

// 2. Verified Rider Authentication
const requireRider = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).json({ status: "unauthorized", message: "Please log in as a rider." });
    }
    const token = authorization.slice(7).trim();
    if (!token) {
      return res.status(401).json({ status: "unauthorized", message: "Authentication token missing." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.id) {
      return res.status(401).json({ status: "unauthorized", message: "Invalid session." });
    }

    const rider = await User.findById(decoded.id).select("-password -otp -otp_expiry").lean();
    if (!rider || rider.user_type !== "rider") {
      return res.status(403).json({ status: "forbidden", message: "Rider access required." });
    }
    if (!rider.is_active) {
      return res.status(403).json({ status: "forbidden", message: "Rider account is inactive." });
    }

    req.rider = rider;
    return next();
  } catch (error) {
    return res.status(401).json({ status: "unauthorized", message: "Session expired or invalid." });
  }
};

// 3. Admin Authentication
const requireAdmin = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).json({ status: "unauthorized", message: "Please log in as an administrator." });
    }
    const token = authorization.slice(7).trim();
    if (!token) {
      return res.status(401).json({ status: "unauthorized", message: "Authentication token is missing." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.id || decoded.admin !== true) {
      return res.status(403).json({ status: "forbidden", message: "Administrator access is required." });
    }

    const admin = await Admin.findById(decoded.id).select("-password -otp -otp_expiry").lean();
    if (!admin) {
      return res.status(401).json({ status: "unauthorized", message: "Administrator account not found." });
    }
    if (!admin.is_active) {
      return res.status(403).json({ status: "forbidden", message: "Your administrator account is inactive." });
    }

    req.admin = {
      id: String(admin._id),
      username: admin.username,
      roles: Array.isArray(admin.roles) ? admin.roles : [],
      user_type: admin.user_type,
    };

    return next();
  } catch (error) {
    return res.status(401).json({ status: "unauthorized", message: "Session expired or invalid." });
  }
};

// 4. GM-Level Admin Authentication
const requireGMForReports = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).json({ status: "unauthorized", message: "Please log in as an administrator." });
    }
    const token = authorization.slice(7).trim();
    if (!token) {
      return res.status(401).json({ status: "unauthorized", message: "Authentication token missing." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.id || decoded.admin !== true) {
      return res.status(401).json({ status: "unauthorized", message: "Invalid administrator session." });
    }

    const admin = await Admin.findById(decoded.id).select("-password -otp -otp_expiry").lean();
    if (!admin) {
      return res.status(401).json({ status: "unauthorized", message: "Administrator account not found." });
    }
    if (!admin.is_active) {
      return res.status(403).json({ status: "forbidden", message: "Your administrator account is inactive." });
    }

    const assignedRoles = Array.isArray(admin.roles)
      ? admin.roles.map((role) => String(role).toLowerCase())
      : [];

    const isGM = String(admin.user_type || "").toLowerCase() === "gm" || assignedRoles.includes("gm");

    if (!isGM) {
      return res.status(403).json({ status: "forbidden", message: "Only the General Manager can perform this action." });
    }

    req.reportAdmin = {
      id: String(admin._id),
      username: admin.username,
      roles: assignedRoles,
    };

    return next();
  } catch (error) {
    return res.status(401).json({ status: "unauthorized", message: "Session expired or invalid." });
  }
};

// 5. Rider Request Management Authorization (GM or Customer Support)
const requireRiderManagementAccess = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) {
      return res.status(401).json({ status: "unauthorized", message: "Please log in as an administrator." });
    }
    const token = authorization.slice(7).trim();
    if (!token) {
      return res.status(401).json({ status: "unauthorized", message: "Authentication token missing." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.id || decoded.admin !== true) {
      return res.status(401).json({ status: "unauthorized", message: "Invalid administrator session." });
    }

    const admin = await Admin.findById(decoded.id).select("-password -otp -otp_expiry").lean();
    if (!admin) {
      return res.status(401).json({ status: "unauthorized", message: "Administrator account not found." });
    }
    if (!admin.is_active) {
      return res.status(403).json({ status: "forbidden", message: "Your administrator account is inactive." });
    }

    const roles = Array.isArray(admin.roles)
      ? admin.roles.map((role) => String(role).toLowerCase())
      : [];
    const userType = String(admin.user_type || "").toLowerCase();

    const permitted = userType === "gm" || roles.includes("gm") || roles.includes("customersupport");
    if (!permitted) {
      return res.status(403).json({ status: "forbidden", message: "You do not have permission to manage rider requests." });
    }

    req.riderManager = { id: String(admin._id), username: admin.username, roles, userType };
    return next();
  } catch (error) {
    return res.status(401).json({ status: "unauthorized", message: "Session expired or invalid." });
  }
};

/* =========================================================
   MULTER UPLOAD HANDLERS
========================================================= */

const profileUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, callback) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/webp"];
    if (!allowedTypes.includes(file.mimetype)) {
      return callback(new Error("Only JPEG, PNG, and WEBP images are allowed."));
    }
    callback(null, true);
  },
});

const promotionUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 2, fields: 30, fieldSize: 1024 * 1024 },
  fileFilter: (req, file, callback) => {
    const allowedTypes = {
      banner: ["image/jpeg", "image/png", "image/webp"],
      video: ["video/mp4", "video/webm", "video/quicktime"],
    };
    if (!allowedTypes[file.fieldname]) {
      return callback(new Error("Unexpected upload field."));
    }
    if (!allowedTypes[file.fieldname].includes(file.mimetype)) {
      return callback(new Error(file.fieldname === "banner" ? "Banner must be JPG, PNG, or WEBP." : "Video must be MP4, WEBM, or MOV."));
    }
    callback(null, true);
  },
});

/* =========================================================
   GOOGLE DRIVE FILE STORAGE SERVICES
========================================================= */

async function uploadProfileImage(file, userType) {
  const folderId = userType === "rider"
    ? process.env.GOOGLE_DRIVE_RIDERS_FOLDER_ID
    : process.env.GOOGLE_DRIVE_CUSTOMERS_FOLDER_ID;

  if (!folderId) {
    throw new Error(`Google Drive folder ID missing for ${userType}.`);
  }

  const extensionByMimeType = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
  };
  const extension = extensionByMimeType[file.mimetype];
  const fileName = `profile_${Date.now()}_${crypto.randomBytes(6).toString("hex")}.${extension}`;

  const uploadedFile = await drive.files.create({
    requestBody: { name: fileName, mimeType: file.mimetype, parents: [folderId] },
    media: { mimeType: file.mimetype, body: Readable.from(file.buffer) },
    fields: "id, name",
  });

  const fileId = uploadedFile.data.id;
  try {
    await drive.permissions.create({
      fileId,
      requestBody: { type: "anyone", role: "reader" },
    });
    return { fileId, url: `https://drive.google.com/uc?export=view&id=${fileId}` };
  } catch (error) {
    await drive.files.delete({ fileId }).catch(() => {});
    throw error;
  }
}

async function uploadPromotionFileToDrive(file, title) {
  const folderId = process.env.GOOGLE_DRIVE_ADVERTISEMENTS_FOLDER_ID;
  if (!folderId) {
    throw new Error("Google Drive advertisements folder is not configured.");
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
  const safeTitle = String(title || "promotion").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 48);
  const filename = `${safeTitle}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}.${extension}`;

  const uploaded = await drive.files.create({
    requestBody: { name: filename, mimeType: file.mimetype, parents: [folderId] },
    media: { mimeType: file.mimetype, body: Readable.from(file.buffer) },
    fields: "id,name",
  });

  const fileId = uploaded.data.id;
  try {
    await drive.permissions.create({
      fileId,
      requestBody: { type: "anyone", role: "reader" },
    });
  } catch (error) {
    await drive.files.delete({ fileId }).catch(() => {});
    throw error;
  }

  return { fileId, url: `https://drive.google.com/uc?export=view&id=${fileId}` };
}

// Strict Drive URL file ID extractor
const extractDriveFileId = (rawUrl) => {
  if (!rawUrl || typeof rawUrl !== "string") return null;
  try {
    const parsed = new URL(rawUrl);
    const validHosts = ["drive.google.com", "docs.google.com"];
    if (!validHosts.includes(parsed.hostname)) return null;

    const queryId = parsed.searchParams.get("id");
    if (queryId) return queryId;

    const match = parsed.pathname.match(/\/(?:file\/d|d)\/([a-zA-Z0-9_-]+)/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
};

function getProfileImageUrl(imageUrl) {
  const fileId = extractDriveFileId(imageUrl);
  return fileId ? `https://drive.google.com/thumbnail?id=${encodeURIComponent(fileId)}&sz=w400` : imageUrl || "";
}

async function deleteOldProfilePhoto(imageUrl, newFileId) {
  const oldFileId = extractDriveFileId(imageUrl);
  if (!oldFileId || oldFileId === newFileId) return;
  try {
    await drive.files.delete({ fileId: oldFileId });
  } catch (error) {
    console.error("Failed to delete previous profile photo:", error.message);
  }
}

/* =========================================================
   USER & RIDER AUTHENTICATION APIS
========================================================= */

app.post("/signup", (req, res, next) => {
  profileUpload.single("profile_image")(req, res, (error) => {
    if (!error) return next();
    return res.status(400).json({ status: "upload_error", message: error.message });
  });
}, async (req, res) => {
  let uploadedDriveFileId = null;
  try {
    const { username, first_name, last_name, phone, email, user_type, password, confirm_password, latitude, longitude } = req.body;

    if (!username?.trim() || !first_name?.trim() || !last_name?.trim() || !phone?.trim() || !email?.trim() || !user_type || !password || !confirm_password) {
      return res.status(400).json({ status: "missing_fields", message: "Please complete all required fields." });
    }
    if (!["user", "rider"].includes(user_type)) {
      return res.status(400).json({ status: "invalid_user_type" });
    }
    if (username.trim().length < 6) {
      return res.status(400).json({ status: "invalid_username", message: "Username must be at least 6 characters." });
    }
    if (password !== confirm_password) {
      return res.status(400).json({ status: "password_mismatch" });
    }
    if (password.length < 8) {
      return res.status(400).json({ status: "weak_password", message: "Password must be at least 8 characters." });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      if (existingUser.is_verified) {
        return res.status(409).json({ status: "user_exists" });
      }
      const otp = generateOTP();
      existingUser.otp = otp;
      existingUser.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
      await existingUser.save();
      await sendOTP(normalizedEmail, otp);
      return res.json({ status: "otp_resent" });
    }

    let profileImageUrl = "";
    if (req.file) {
      const uploadedImage = await uploadProfileImage(req.file, user_type);
      uploadedDriveFileId = uploadedImage.fileId;
      profileImageUrl = uploadedImage.url;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

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
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
      is_verified: false,
    };

    if (user_type === "rider") {
      userData.rider_location = { lat: Number(latitude) || 0, lng: Number(longitude) || 0 };
    }

    const newUser = await User.create(userData);
    try {
      await sendOTP(normalizedEmail, otp);
    } catch (emailError) {
      await User.deleteOne({ _id: newUser._id });
      if (uploadedDriveFileId) await drive.files.delete({ fileId: uploadedDriveFileId }).catch(() => {});
      return res.status(502).json({ status: "otp_email_failed", message: "Unable to send verification OTP." });
    }

    return res.status(201).json({ status: "signup_success_otp_sent", message: "OTP sent successfully.", profile_image: profileImageUrl });
  } catch (error) {
    if (uploadedDriveFileId) await drive.files.delete({ fileId: uploadedDriveFileId }).catch(() => {});
    return res.status(500).json({ status: "error", message: "Signup failed." });
  }
});

app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email: email?.trim().toLowerCase() });
    if (!user) return res.status(404).json({ status: "not_found" });
    if (user.is_verified) return res.status(400).json({ status: "already_verified" });
    if (user.otp !== otp || (user.otp_expiry && new Date() > user.otp_expiry)) {
      return res.status(400).json({ status: "invalid_or_expired_otp" });
    }

    user.is_verified = true;
    user.otp = null;
    user.otp_expiry = null;
    await user.save();

    res.json({ status: "account_verified" });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password, user_type } = req.body;
    const user = await User.findOne({ email: email?.trim().toLowerCase() });
    if (!user) return res.status(401).json({ status: "invalid_credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ status: "invalid_credentials" });

    if (!user.is_verified) {
      return res.json({ status: "otp_required", email: user.email });
    }
    if (user.user_type !== "admin" && user.user_type !== user_type) {
      return res.status(403).json({ status: "invalid_credentials" });
    }

    const token = jwt.sign({ id: user._id, role: user.user_type }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ status: "login_success", token, user });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ status: "missing_email" });
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) return res.status(404).json({ status: "not_found" });
    if (user.is_verified) return res.status(400).json({ status: "already_verified" });

    const otp = generateOTP();
    user.otp = otp;
    user.otp_expiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();
    await sendOTP(user.email, otp);

    return res.json({ status: "otp_resent" });
  } catch (err) {
    return res.status(500).json({ status: "error" });
  }
});

/* =========================================================
   PROTECTED PROFILE MANAGEMENT APIS
========================================================= */

// Authenticated user profile retrieval
app.get("/user/profile", requireUser, async (req, res) => {
  return res.status(200).json({
    status: "success",
    user: {
      ...req.user,
      profile_image: getProfileImageUrl(req.user.profile_image),
    },
  });
});

// Authenticated profile update
app.put("/update-profile", requireUser, async (req, res) => {
  try {
    const { first_name, last_name, phone } = req.body;
    const user = await User.findById(req.user._id);

    if (first_name !== undefined) {
      if (typeof first_name !== "string" || !first_name.trim()) {
        return res.status(400).json({ status: "invalid_first_name", message: "First name cannot be empty." });
      }
      user.first_name = first_name.trim();
    }
    if (last_name !== undefined) {
      if (typeof last_name !== "string" || !last_name.trim()) {
        return res.status(400).json({ status: "invalid_last_name", message: "Last name cannot be empty." });
      }
      user.last_name = last_name.trim();
    }
    if (phone !== undefined) {
      if (typeof phone !== "string" || !phone.trim()) {
        return res.status(400).json({ status: "invalid_phone", message: "Phone number cannot be empty." });
      }
      user.phone = phone.trim();
    }

    await user.save();
    return res.status(200).json({
      status: "updated_successfully",
      message: "Profile updated successfully.",
      user: {
        _id: user._id,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        phone: user.phone,
        profile_image: user.profile_image || "",
        user_type: user.user_type,
      },
    });
  } catch (err) {
    return res.status(500).json({ status: "error", message: "Failed to update profile." });
  }
});

// Authenticated profile photo upload
app.post("/upload-profile-photo", requireUser, (req, res, next) => {
  profileUpload.single("photo")(req, res, (error) => {
    if (error) return res.status(400).json({ status: "upload_error", message: error.message });
    next();
  });
}, async (req, res) => {
  let uploadedFileId = null;
  try {
    if (!req.file) return res.status(400).json({ status: "missing_photo", message: "Please select a photo." });

    const user = await User.findById(req.user._id);
    const oldProfileImage = user.profile_image || null;

    const uploadedImage = await uploadProfileImage(req.file, user.user_type);
    uploadedFileId = uploadedImage.fileId;

    user.profile_image = uploadedImage.url;
    await user.save();

    if (oldProfileImage) {
      await deleteOldProfilePhoto(oldProfileImage, uploadedImage.fileId);
    }

    return res.status(200).json({
      status: "photo_uploaded",
      message: "Profile photo uploaded successfully.",
      profile_image: uploadedImage.url,
    });
  } catch (error) {
    if (uploadedFileId) await drive.files.delete({ fileId: uploadedFileId }).catch(() => {});
    return res.status(500).json({ status: "upload_failed", message: "Failed to upload photo." });
  }
});

/* =========================================================
   PROTECTED DONATIONS & RIDER PICKUP APIS
========================================================= */

app.post("/donate", requireUser, async (req, res) => {
  try {
    const otp = generateOTP();
    const donation = await Donation.create({
      ...req.body,
      donor_email: req.user.email,
      otp,
      otp_expiry: new Date(Date.now() + 10 * 60 * 1000),
    });

    await sendOTP(req.user.email, otp);
    res.json({ status: "otp_sent", donation_id: donation._id });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Donation failed." });
  }
});

app.post("/verify-donate-otp", async (req, res) => {
  try {
    const { donation_id, otp, rider_email } = req.body;
    const donation = await Donation.findById(donation_id);
    if (!donation) return res.status(404).json({ status: "not_found" });

    if (donation.otp !== otp) {
      return res.status(400).json({ status: "invalid_otp" });
    }

    donation.is_verified = true;
    donation.otp = null;
    donation.otp_expiry = null;
    if (rider_email) {
      donation.rider_email = rider_email;
      donation.donation_status = "picked";
    }

    await donation.save();
    res.json({ status: rider_email ? "donation_verified_and_picked" : "donation_verified" });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

// Authenticated retrieval of requests created by current user
app.get("/my-requests", requireUser, async (req, res) => {
  try {
    const requests = await Donation.find({ donor_email: req.user.email }).sort({ createdAt: -1 });
    res.json({ status: "success", requests });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

// Authenticated rider endpoints
app.get("/rider/available-pickups", requireRider, async (req, res) => {
  try {
    const donations = await Donation.find({ donation_status: "not_picked", is_verified: true });
    res.json({ status: "success", donations });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.post("/rider/pickup", requireRider, async (req, res) => {
  try {
    const { donation_id } = req.body;
    const donation = await Donation.findOneAndUpdate(
      { _id: donation_id, donation_status: "not_picked" },
      { $set: { rider_email: req.rider.email, donation_status: "picked" } },
      { new: true }
    );
    if (!donation) {
      return res.status(400).json({ status: "unavailable", message: "Donation already claimed or not found." });
    }
    res.json({ status: "pickup_locked", donation });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.post("/rider/mark-delivered", requireRider, async (req, res) => {
  try {
    const { donation_id } = req.body;
    const donation = await Donation.findOneAndUpdate(
      { _id: donation_id, rider_email: req.rider.email, donation_status: "picked" },
      { $set: { donation_status: "delivered" } },
      { new: true }
    );
    if (!donation) {
      return res.status(400).json({ status: "error", message: "Donation not assigned to you or invalid status." });
    }
    res.json({ status: "delivered_success" });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.get("/rider/my-rides", requireRider, async (req, res) => {
  try {
    const rides = await Donation.find({ rider_email: req.rider.email }).sort({ createdAt: -1 });
    res.json({ status: "success", rides });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

/* =========================================================
   BECOME RIDER ONBOARDING WORKFLOW
========================================================= */

app.post("/rider/verify-email", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ status: "missing_email" });
    const normalizedEmail = email.trim().toLowerCase();

    const existingRider = await User.findOne({ email: normalizedEmail, user_type: "rider" });
    if (existingRider) {
      return res.status(409).json({ status: "rider_already_exists" });
    }

    const existingRequest = await BecomeRider.findOne({
      email: normalizedEmail,
      status: { $in: ["pending", "under_review", "approved"] },
    });
    if (existingRequest) {
      return res.status(409).json({ status: "request_already_exists" });
    }

    return res.status(200).json({ status: "email_eligible" });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

app.post("/rider/request-account", async (req, res) => {
  try {
    const { first_name, last_name, email, phone, profile_image_data } = req.body || {};
    if (!first_name?.trim() || !last_name?.trim() || !email?.trim() || !phone?.trim()) {
      return res.status(400).json({ status: "missing_fields", message: "Please fill in all required fields." });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const base64Match = profile_image_data?.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/);
    if (!base64Match) {
      return res.status(400).json({ status: "invalid_profile_image", message: "Valid JPEG camera photo required." });
    }

    const imageBuffer = Buffer.from(base64Match[1], "base64");
    if (imageBuffer.length > 5 * 1024 * 1024) {
      return res.status(400).json({ status: "file_too_large", message: "Photo cannot exceed 5MB." });
    }

    const uploadedImage = await uploadProfileImage(
      { buffer: imageBuffer, mimetype: "image/jpeg" },
      "rider"
    );

    const riderRequest = await BecomeRider.create({
      first_name: first_name.trim(),
      last_name: last_name.trim(),
      email: normalizedEmail,
      phone: phone.trim(),
      profile_image: uploadedImage.url,
      status: "pending",
    });

    await sendEmail({
      to: normalizedEmail,
      subject: "Your DWJD Rider Account Request Has Been Received",
      html: `<h2>Hello ${escapeHtml(first_name)},</h2><p>Your rider application has been received and is under review.</p>`,
    }).catch(() => {});

    return res.status(201).json({ status: "request_submitted", request_id: riderRequest._id });
  } catch (error) {
    return res.status(500).json({ status: "error", message: "Submission failed." });
  }
});

/* =========================================================
   ADMINISTRATOR AUTHENTICATION & DIRECTORY (PROTECTED)
========================================================= */

app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ status: "missing_fields", message: "Username and password required." });
    }

    const admin = await Admin.findOne({ username });
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ status: "invalid_credentials" });
    }
    if (!admin.is_active) {
      return res.status(403).json({ status: "account_inactive" });
    }

    const token = jwt.sign({ id: admin._id, role: admin.user_type, admin: true }, process.env.JWT_SECRET, { expiresIn: "7d" });
    return res.json({ status: "login_success", token, admin });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

// Restricted to GM only
app.post("/admin/create-admin", requireGMForReports, async (req, res) => {
  try {
    const { username, email, first_name, last_name, phone, roles } = req.body;
    if (!username?.trim() || !email?.trim() || !first_name?.trim() || !last_name?.trim() || !phone?.trim() || !Array.isArray(roles) || roles.length === 0) {
      return res.status(400).json({ status: "missing_fields", message: "All fields and at least one role are required." });
    }

    const normalizedUsername = username.trim();
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim();

    const existingAdmin = await Admin.findOne({
      $or: [{ username: normalizedUsername }, { email: normalizedEmail }, { phone: normalizedPhone }],
    });
    if (existingAdmin) {
      return res.status(409).json({ status: "admin_exists", message: "Admin username, email, or phone already exists." });
    }

    const temporaryPassword = crypto.randomBytes(12).toString("base64url");
    const hashedPassword = await bcrypt.hash(temporaryPassword, 12);

    const newAdmin = await Admin.create({
      username: normalizedUsername,
      email: normalizedEmail,
      first_name: first_name.trim(),
      last_name: last_name.trim(),
      phone: normalizedPhone,
      password: hashedPassword,
      user_type: "admin",
      roles: [...new Set(roles)],
      is_verified: true,
      is_active: true,
    });

    await sendEmail({
      to: normalizedEmail,
      subject: "Your DWJD Admin Account Credentials",
      html: `<h2>Welcome ${escapeHtml(first_name)}</h2><p>Username: ${escapeHtml(normalizedUsername)}</p><p>Temporary Password: ${escapeHtml(temporaryPassword)}</p>`,
    }).catch(() => {});

    return res.status(201).json({ status: "admin_created", admin: newAdmin });
  } catch (error) {
    return res.status(500).json({ status: "error", message: "Failed to create administrator." });
  }
});

// Restricted to GM only
app.get("/admin/admins", requireGMForReports, async (req, res) => {
  try {
    const admins = await Admin.find({}).select("-password -otp -otp_expiry").sort({ createdAt: -1 }).lean();
    return res.status(200).json({ status: "success", count: admins.length, admins });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

// Restricted to GM only
app.patch("/admin/admins/:adminId/status", requireGMForReports, async (req, res) => {
  try {
    const { adminId } = req.params;
    const { is_active } = req.body;
    if (typeof is_active !== "boolean") {
      return res.status(400).json({ status: "error", message: "is_active must be a boolean." });
    }

    const admin = await Admin.findByIdAndUpdate(adminId, { $set: { is_active } }, { new: true }).select("-password");
    if (!admin) return res.status(404).json({ status: "not_found" });

    return res.json({ status: "success", admin });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

// Directory - Protected by General Admin Auth
app.get("/admin/dashboard/directory", requireAdmin, async (req, res) => {
  try {
    const [users, admins, riders] = await Promise.all([
      User.find({}).select("-password -otp -otp_expiry").sort({ createdAt: -1 }).lean(),
      Admin.find({}).select("-password -otp -otp_expiry").sort({ createdAt: -1 }).lean(),
      BecomeRider.find({}).select("-password -otp -otp_expiry").sort({ createdAt: -1 }).lean(),
    ]);

    return res.status(200).json({
      status: "success",
      data: { users, admins, riders },
      counts: { users: users.length, admins: admins.length, riders: riders.length, total: users.length + admins.length + riders.length },
    });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

/* =========================================================
   ADMIN RIDER APPLICATION MANAGEMENT
========================================================= */

app.get("/admin/rider-requests", requireRiderManagementAccess, async (req, res) => {
  try {
    const requests = await BecomeRider.find({}).sort({ createdAt: -1 }).lean();
    return res.json({ status: "success", count: requests.length, requests });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

app.patch("/admin/rider-requests/:requestId/status", requireRiderManagementAccess, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { status, rejection_reason } = req.body;

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ status: "error", message: "Invalid status value." });
    }

    const updated = await BecomeRider.findOneAndUpdate(
      { _id: requestId, status: { $in: ["pending", "under_review"] } },
      {
        $set: {
          status,
          reviewed_by: req.riderManager.id,
          reviewed_at: new Date(),
          rejection_reason: status === "rejected" ? String(rejection_reason || "").trim() : "",
        },
      },
      { new: true }
    );

    if (!updated) return res.status(400).json({ status: "error", message: "Request cannot be modified in its current state." });
    return res.json({ status: "success", request: updated });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

app.post("/admin/rider-requests/:requestId/create-account", requireRiderManagementAccess, async (req, res) => {
  let createdUserId = null;
  try {
    const { requestId } = req.params;
    const riderRequest = await BecomeRider.findById(requestId);
    if (!riderRequest || riderRequest.status !== "approved") {
      return res.status(400).json({ status: "error", message: "Rider request must be approved first." });
    }

    const email = riderRequest.email.trim().toLowerCase();
    if (await User.findOne({ email })) {
      return res.status(409).json({ status: "error", message: "Account already exists for this email." });
    }

    const defaultPassword = crypto.randomBytes(12).toString("base64url");
    const hashedPassword = await bcrypt.hash(defaultPassword, 12);
    const username = `rider_${Date.now()}`;

    const rider = await User.create({
      username,
      email,
      password: hashedPassword,
      first_name: riderRequest.first_name,
      last_name: riderRequest.last_name,
      phone: riderRequest.phone,
      user_type: "rider",
      is_verified: true,
      is_active: true,
    });
    createdUserId = rider._id;

    riderRequest.status = "account_created";
    riderRequest.created_user_id = rider._id;
    riderRequest.account_created_at = new Date();
    await riderRequest.save();

    await sendEmail({
      to: email,
      subject: "Welcome to DWJD - Rider Credentials",
      html: `<h2>Rider Account Approved</h2><p>Username: ${username}</p><p>Password: ${defaultPassword}</p>`,
    }).catch(() => {});

    return res.status(201).json({ status: "rider_created", rider });
  } catch (error) {
    if (createdUserId) await User.deleteOne({ _id: createdUserId }).catch(() => {});
    return res.status(500).json({ status: "error" });
  }
});

/* =========================================================
   ADVERTISEMENTS & CAMPAIGN MANAGEMENT
========================================================= */

// Protected Admin Campaign Creation with Strict Whitelisting
app.post("/admin/add-advertisement", requireAdmin, async (req, res) => {
  try {
    const { brand_name, company_name, title, description, promotion_type, placement, start_date, end_date, amount_paid, contact_email, target_url } = req.body;

    if (!brand_name || !title || !start_date || !end_date) {
      return res.status(400).json({ status: "error", message: "Missing required advertisement fields." });
    }

    const safeAdvertisement = await Advertisement.create({
      brand_name: String(brand_name).trim(),
      company_name: String(company_name || "").trim(),
      title: String(title).trim(),
      description: String(description || "").trim(),
      promotion_type: promotion_type || "banner",
      placement: placement || "home_page",
      start_date: new Date(start_date),
      end_date: new Date(end_date),
      amount_paid: Number(amount_paid) || 0,
      contact_email: String(contact_email || "").trim().toLowerCase(),
      target_url: String(target_url || "").trim(),
      status: "pending",
      payment_status: "pending",
      is_active: false,
    });

    return res.status(201).json({ status: "advertisement_added", advertisement: safeAdvertisement });
  } catch (err) {
    return res.status(500).json({ status: "error", message: "Failed to add advertisement." });
  }
});

// Admin-only retrieval of all promotions
app.get("/advertisements", requireAdmin, async (req, res) => {
  try {
    const ads = await Advertisement.find().sort({ createdAt: -1 });
    res.json({ status: "success", ads });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

// Public Submission Endpoint
app.post("/advertisements/request", (req, res, next) => {
  promotionUpload.fields([{ name: "banner", maxCount: 1 }, { name: "video", maxCount: 1 }])(req, res, (error) => {
    if (!error) return next();
    return res.status(400).json({ status: "error", message: error.message });
  });
}, async (req, res) => {
  const uploadedFileIds = [];
  try {
    const { brand_name, company_name, contact_person, contact_email, contact_phone, title, description, promotion_type, target_url, placement, start_date, end_date, amount_paid } = req.body;

    if (!brand_name?.trim() || !contact_email?.trim() || !title?.trim() || !start_date || !end_date) {
      return res.status(400).json({ status: "error", message: "Missing required fields." });
    }

    let imageUpload = null;
    let videoUpload = null;

    if (req.files?.banner?.[0]) {
      imageUpload = await uploadPromotionFileToDrive(req.files.banner[0], title);
      uploadedFileIds.push(imageUpload.fileId);
    }
    if (req.files?.video?.[0]) {
      videoUpload = await uploadPromotionFileToDrive(req.files.video[0], title);
      uploadedFileIds.push(videoUpload.fileId);
    }

    const advertisement = await Advertisement.create({
      brand_name: brand_name.trim(),
      company_name: company_name?.trim(),
      contact_person: contact_person?.trim(),
      contact_email: contact_email.trim().toLowerCase(),
      contact_phone: contact_phone?.trim(),
      title: title.trim(),
      description: description?.trim(),
      promotion_type: promotion_type || "banner",
      image_url: imageUpload?.url || "",
      video_url: videoUpload?.url || "",
      image_drive_file_id: imageUpload?.fileId || "",
      video_drive_file_id: videoUpload?.fileId || "",
      target_url: target_url?.trim() || "",
      placement: placement || "home_page",
      start_date: new Date(start_date),
      end_date: new Date(end_date),
      amount_paid: Number(amount_paid) || 0,
      status: "pending",
      payment_status: "pending",
      is_active: false,
    });

    return res.status(201).json({ status: "success", advertisement });
  } catch (error) {
    for (const fileId of uploadedFileIds) {
      await drive.files.delete({ fileId }).catch(() => {});
    }
    return res.status(500).json({ status: "error", message: "Failed to submit advertisement." });
  }
});

// Admin Approval
app.patch("/admin/advertisements/:id/approve", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { approved_amount } = req.body;
    const amount = Number(approved_amount);

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ status: "error", message: "Please provide a valid approved amount." });
    }

    const ad = await Advertisement.findById(id);
    if (!ad) return res.status(404).json({ status: "error", message: "Not found." });
    if (ad.payment_status === "paid") {
      return res.status(400).json({ status: "error", message: "Cannot edit paid campaign." });
    }

    ad.status = "approved";
    ad.approved_amount = amount;
    ad.currency = "INR";
    ad.reviewed_at = new Date();
    ad.reviewed_by = req.admin.id;
    ad.payment_link_id = "";
    ad.payment_link_url = "";
    await ad.save();

    return res.json({ status: "success", message: "Campaign approved.", advertisement: ad });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

// Admin Payment Link Generation
app.post("/admin/advertisements/:id/payment-link", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const ad = await Advertisement.findById(id);

    if (!ad || ad.status !== "approved" || !ad.approved_amount) {
      return res.status(400).json({ status: "error", message: "Campaign must be approved with an amount." });
    }
    if (ad.payment_status === "paid") {
      return res.status(409).json({ status: "error", message: "Already paid." });
    }
    if (ad.payment_link_url) {
      return res.json({ status: "exists", payment_link_url: ad.payment_link_url });
    }

    const amountInPaise = Math.round(Number(ad.approved_amount) * 100);
    const paymentLink = await razorpay.paymentLink.create({
      amount: amountInPaise,
      currency: "INR",
      accept_partial: false,
      description: `DWJD Ad: ${ad.title}`,
      customer: { name: ad.brand_name || "Advertiser", email: ad.contact_email },
      reference_id: `ad_${ad._id}`,
    });

    ad.payment_link_id = paymentLink.id;
    ad.payment_link_url = paymentLink.short_url;
    ad.payment_link_sent_at = new Date();
    await ad.save();

    await sendEmail({
      to: ad.contact_email,
      subject: "DWJD Promotion Payment Link",
      html: `<p>Pay ₹${ad.approved_amount}: <a href="${paymentLink.short_url}">Complete Payment</a></p>`,
    }).catch(() => {});

    return res.json({ status: "success", payment_link_url: paymentLink.short_url });
  } catch (error) {
    return res.status(500).json({ status: "error", message: "Failed to generate link." });
  }
});

// Admin Manual Activation (Paid + Scheduled)
app.patch("/admin/advertisements/:id/activate", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const ad = await Advertisement.findById(id);
    if (!ad) return res.status(404).json({ status: "not_found" });

    if (ad.status !== "approved" || ad.payment_status !== "paid") {
      return res.status(400).json({ status: "error", message: "Requires approval and completed payment." });
    }

    const now = new Date();
    if (now < new Date(ad.start_date) || now > new Date(ad.end_date)) {
      return res.status(400).json({ status: "error", message: "Campaign outside scheduled dates." });
    }

    ad.is_active = true;
    await ad.save();
    return res.json({ status: "success", message: "Activated successfully." });
  } catch (error) {
    return res.status(500).json({ status: "error" });
  }
});

// Public Active Advertisements
app.get("/advertisements/active", async (req, res) => {
  try {
    const now = new Date();
    const advertisements = await Advertisement.find({
      status: "approved",
      payment_status: "paid",
      is_active: true,
      start_date: { $lte: now },
      end_date: { $gte: now },
    }).select("title brand_name description image_url video_url target_url placement").lean();

    return res.json({ success: true, count: advertisements.length, advertisements });
  } catch (error) {
    return res.status(500).json({ success: false });
  }
});

/* =========================================================
   RAZORPAY PAYMENT LINK WEBHOOK (ATOMIC & IDEMPOTENT)
========================================================= */

app.post("/webhooks/razorpay", async (req, res) => {
  try {
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
    if (!webhookSecret || !req.rawBody) {
      return res.status(400).json({ message: "Bad Configuration / Payload." });
    }

    const receivedSignature = req.headers["x-razorpay-signature"];
    const expectedSignature = crypto.createHmac("sha256", webhookSecret).update(req.rawBody).digest();
    const signatureBuf = Buffer.from(receivedSignature || "", "hex");

    if (expectedSignature.length !== signatureBuf.length || !crypto.timingSafeEqual(expectedSignature, signatureBuf)) {
      return res.status(401).json({ message: "Invalid Signature." });
    }

    const event = req.body?.event;
    if (event !== "payment_link.paid") {
      return res.status(200).json({ status: "ignored" });
    }

    const paymentLink = req.body?.payload?.payment_link?.entity;
    const payment = req.body?.payload?.payment?.entity;
    if (!paymentLink?.id || !payment?.id) {
      return res.status(400).json({ message: "Missing event payload." });
    }

    // Atomic update prevents concurrent duplicate webhooks
    const updated = await Advertisement.findOneAndUpdate(
      { payment_link_id: paymentLink.id, payment_status: { $ne: "paid" } },
      {
        $set: {
          payment_status: "paid",
          payment_reference: payment.id,
          payment_paid_at: new Date(),
          is_active: false,
        },
      },
      { new: true }
    );

    return res.status(200).json({ success: true, updated: Boolean(updated) });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

/* =========================================================
   PROMOTION MEDIA CLEANUP WORKER (CRON)
========================================================= */

const cleanupExpiredPromotionMedia = async () => {
  const now = new Date();
  const folderId = process.env.GOOGLE_DRIVE_ADVERTISEMENTS_FOLDER_ID;

  // 1. Deactivate active expired ads
  await Advertisement.updateMany(
    { is_active: true, end_date: { $lte: now } },
    { $set: { is_active: false } }
  );

  // 2. Strict media exists match
  const mediaExists = {
    $or: [
      { image_drive_file_id: { $type: "string", $ne: "" } },
      { video_drive_file_id: { $type: "string", $ne: "" } },
      { image_url: { $type: "string", $ne: "" } },
      { video_url: { $type: "string", $ne: "" } },
    ],
  };

  const candidates = await Advertisement.find({
    end_date: { $lte: now },
    media_cleanup_status: { $in: ["pending", "failed"] },
    ...mediaExists,
  }).limit(50);

  for (const ad of candidates) {
    try {
      const imgId = ad.image_drive_file_id || extractDriveFileId(ad.image_url);
      const vidId = ad.video_drive_file_id || extractDriveFileId(ad.video_url);
      const toDelete = [...new Set([imgId, vidId].filter(Boolean))];

      for (const fileId of toDelete) {
        const file = await drive.files.get({ fileId, fields: "id, parents, trashed" }).catch(() => null);
        if (file?.data && !file.data.trashed && file.data.parents?.includes(folderId)) {
          await drive.files.delete({ fileId }).catch(() => {});
        }
      }

      ad.image_url = "";
      ad.video_url = "";
      ad.image_drive_file_id = "";
      ad.video_drive_file_id = "";
      ad.media_cleanup_status = "completed";
      ad.media_cleaned_at = new Date();
      await ad.save();
    } catch (err) {
      ad.media_cleanup_status = "failed";
      ad.media_cleanup_error = err.message;
      await ad.save();
    }
  }
};

cron.schedule("*/5 * * * *", cleanupExpiredPromotionMedia);

/* =========================================================
   SERVER INITIALIZATION
========================================================= */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));