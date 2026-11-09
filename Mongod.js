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
  const OccasionDonation = require("./models/OccasionDonation");
  const app = express();
  const OAuthLoginCode = require("./models/OAuthLoginCode");
  const cookieParser = require("cookie-parser");
  /* ================= MIDDLEWARE ================= */

  const ALLOWED_ADMIN_ROLES = [
    "gm",
    "admin",
  ];

  const ALLOWED_RESPONSIBILITIES = [
    "create_promotion",
    "create_rider",
  ];

  const googleOAuthClient = new google.auth.OAuth2(
    process.env.GOOGLE_OAUTH_CLIENT_ID,
    process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    process.env.GOOGLE_OAUTH_REDIRECT_URI
  );


  /* ================= MIDDLEWARE ================= */

  // Permanent frontend domains
  const allowedOrigins = [
    "https://www.dwjd.online",
    "https://dwjd.online",
    "https://dwjd-org.vercel.app",
    "http://localhost:5173",
    "http://192.168.1.12:5173",
    "http://localhost:5174"
  ];

  // Allow preview deployments belonging to this Vercel project.
  // Restrict the pattern to this project's deployment naming format.
  const isAllowedVercelPreview = (origin) => {
    return /^https:\/\/project-group-[a-z0-9-]+-kola-afdd1ad9\.vercel\.app$/.test(
      origin
    );
  };

  app.use(
    cors({
      origin: (origin, callback) => {
        if (
          !origin ||
          allowedOrigins.includes(origin) ||
          isAllowedVercelPreview(origin)
        ) {
          return callback(null, true);
        }

        console.error("Blocked CORS origin:", origin);

        return callback(new Error("Not allowed by CORS"));
      },

      methods: [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
      ],

      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "Accept",
      ],

      credentials: true,
    })
  );

  // ADD THIS LINE
  app.use(cookieParser());

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
/* ============================================
   OCCASION DONATION MEDIA UPLOAD
============================================ */

const occasionDonationUpload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 5,
    fields: 30,
    fieldSize: 1024 * 1024,
  },

  fileFilter: (req, file, callback) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "video/mp4",
      "video/webm",
      "video/quicktime",
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return callback(
        new Error(
          "Only JPG, PNG, WEBP, MP4, WEBM and MOV files are allowed."
        )
      );
    }

    callback(null, true);
  },
});

/* ============================================
   OCCASION DONATION USER AUTHENTICATION
   Uses the existing user JWT format.
============================================ */

const requireOccasionDonationUser = async (req, res, next) => {
  try {
    const authorization = req.headers.authorization;

    if (!authorization?.startsWith("Bearer ")) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Please log in to continue.",
      });
    }

    const token = authorization.slice(7).trim();

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (!decoded.id || !["user", "rider"].includes(decoded.role)) {
      return res.status(403).json({
        status: "forbidden",
        message: "A valid user account is required.",
      });
    }

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({
        status: "unauthorized",
        message: "User account not found.",
      });
    }

    if (!user.is_verified) {
      return res.status(403).json({
        status: "account_unverified",
        message: "Please verify your account first.",
      });
    }

    if (user.is_active === false) {
      return res.status(403).json({
        status: "account_inactive",
        message: "Your account is inactive.",
      });
    }

    if (user.user_type !== decoded.role) {
      return res.status(403).json({
        status: "forbidden",
        message: "Account type does not match your session.",
      });
    }

    if (
      decoded.token_version !== undefined &&
      Number(decoded.token_version) !==
        Number(user.token_version ?? 0)
    ) {
      return res.status(401).json({
        status: "session_expired",
        message: "Your session has expired. Please log in again.",
      });
    }

    req.occasionDonationUser = user;

    return next();
  } catch (error) {
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError" ||
      error.name === "NotBeforeError"
    ) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Invalid or expired login session.",
      });
    }

    console.error(
      "Occasion donation authentication error:",
      error
    );

    return res.status(500).json({
      status: "error",
      message: "Unable to authenticate your account.",
    });
  }
};


app.get("/razorpay/public-key", (req, res) => {
  if (!process.env.RAZORPAY_KEY_ID) {
    return res.status(503).json({
      status: "error",
      message: "Razorpay Key ID is not configured.",
    });
  }

  return res.json({
    status: "success",
    key: process.env.RAZORPAY_KEY_ID,
  });
});

/* ============================================
   OCCASION DONATION GOOGLE DRIVE UPLOAD
============================================ */

async function uploadOccasionDonationFile(file, recipientName) {
  const folderId =
    process.env.GOOGLE_DRIVE_OCCASION_DONATIONS_FOLDER_ID;

  if (!folderId) {
    throw new Error(
      "Google Drive occasion donations folder is not configured."
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
    throw new Error("Unsupported occasion donation media format.");
  }

  const safeName = String(recipientName || "occasion")
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .slice(0, 40);

  const fileName =
    `occasion_${safeName}_${Date.now()}_` +
    `${crypto.randomBytes(5).toString("hex")}.${extension}`;

  const uploaded = await drive.files.create({
    requestBody: {
      name: fileName,
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
    // These links are public. Use only if public media access
    // is acceptable for your donation feature.
    await drive.permissions.create({
      fileId,

      requestBody: {
        type: "anyone",
        role: "reader",
      },
    });

    return {
      driveFileId: fileId,

      url: `https://drive.google.com/uc?export=view&id=${fileId}`,

      name: file.originalname,
      mimeType: file.mimetype,
      size: file.size,

      resourceType: file.mimetype.startsWith("video/")
        ? "video"
        : "image",
    };
  } catch (error) {
    await drive.files
      .delete({ fileId })
      .catch((cleanupError) => {
        console.error(
          "Occasion media cleanup error:",
          cleanupError.message
        );
      });

    throw error;
  }
}

/* ============================================
   OCCASION DONATION DATE HELPER
   Frontend sends India date and time.
============================================ */

function getOccasionScheduledAt(dateString, timeString) {
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(dateString || "") ||
    !/^([01]\d|2[0-3]):([0-5]\d)$/.test(timeString || "")
  ) {
    return null;
  }

  const scheduledAt = new Date(
    `${dateString}T${timeString}:00+05:30`
  );

  if (Number.isNaN(scheduledAt.getTime())) {
    return null;
  }

  return scheduledAt;
}
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

console.log("========== ADMIN AUTH DEBUG ==========");
console.log("Decoded token ID:", decoded.id);
console.log("MongoDB database:", Admin.db.name);
console.log("Admin collection:", Admin.collection.name);
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
      // 1. Check authorization header
      const authorization = req.headers.authorization;

      if (!authorization || !authorization.startsWith("Bearer ")) {
        return res.status(401).json({
          status: "unauthorized",
          message: "Please log in as an administrator.",
        });
      }

      // 2. Extract token
      const token = authorization.split(" ")[1];

      // 3. Verify JWT
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET
      );

      if (!decoded.id || decoded.admin !== true) {
        return res.status(403).json({
          status: "forbidden",
          message: "Administrator access is required.",
        });
      }

      // 4. Fetch current admin from MongoDB
      const admin = await Admin.findById(decoded.id)
        .select("-password -otp -otp_expiry")
        .lean();

      if (!admin) {
        return res.status(401).json({
          status: "unauthorized",
          message: "Administrator account not found.",
        });
      }

      // 5. Check account status
      if (!admin.is_active) {
        return res.status(403).json({
          status: "account_inactive",
          message: "Your administrator account is inactive.",
        });
      }

      if (!admin.is_verified) {
        return res.status(403).json({
          status: "account_unverified",
          message: "Your administrator account is not verified.",
        });
      }

      // 6. Assign NEW admin structure
      req.admin = {
        id: String(admin._id),
        username: admin.username,
        email: admin.email,

        user_type: admin.user_type,

        // NEW ROLE FIELD
        role: admin.role,

        // NEW RESPONSIBILITIES FIELD
        responsibilities: Array.isArray(admin.responsibilities)
          ? admin.responsibilities
          : [],

        is_active: admin.is_active,
        is_verified: admin.is_verified,
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
          message: "Invalid or expired authentication token.",
        });
      }

      console.error("Admin authentication error:", error);

      return res.status(500).json({
        status: "error",
        message: "Admin authentication failed.",
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

/* =========================================================
   OCCASION WISHES TOKEN ENCRYPTION
========================================================= */

function getWishEncryptionKey() {
  const key = process.env.WISH_TOKEN_ENCRYPTION_KEY;

  if (!key || !/^[a-f0-9]{64}$/i.test(key)) {
    throw new Error(
      "WISH_TOKEN_ENCRYPTION_KEY must be a 64-character hexadecimal key."
    );
  }

  return Buffer.from(key, "hex");
}

function encryptWishToken(token) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getWishEncryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(token, "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    authTag.toString("hex"),
    encrypted.toString("hex"),
  ].join(":");
}

function decryptWishToken(encryptedValue) {
  const [ivHex, authTagHex, encryptedHex] =
    String(encryptedValue || "").split(":");

  if (!ivHex || !authTagHex || !encryptedHex) {
    throw new Error("Invalid encrypted wishes token.");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getWishEncryptionKey(),
    Buffer.from(ivHex, "hex")
  );

  decipher.setAuthTag(Buffer.from(authTagHex, "hex"));

  return Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

function escapeWishHtml(value) {
  return String(value || "").replace(
    /[&<>"']/g,
    (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character]
  );
}

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

      // 1. Validate required fields
      if (
        !email ||
        !password ||
        !["user", "rider"].includes(user_type)
      ) {
        return res.status(400).json({
          status: "invalid_input",
          message: "Email, password and valid account type are required.",
        });
      }

      // 2. Find account
      const normalizedEmail = email.trim().toLowerCase();

      const user = await User.findOne({
        email: normalizedEmail,
      });

      if (!user) {
        return res.status(401).json({
          status: "invalid_credentials",
          message: "Invalid email or password.",
        });
      }

      // 3. Google-only accounts must use Google login
      if (!user.password) {
        return res.status(401).json({
          status: "invalid_credentials",
          message: "This account uses Google login. Please continue with Google.",
        });
      }

      // 4. Verify password
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.status(401).json({
          status: "invalid_credentials",
          message: "Invalid email or password.",
        });
      }

      // 5. Verify email
      if (!user.is_verified) {
        return res.status(403).json({
          status: "otp_required",
          email: user.email,
        });
      }

      // 6. Enforce account type
      // A converted rider cannot log in through User Login.
      if (user.user_type !== user_type) {
        return res.status(403).json({
          status: "account_type_mismatch",
          message:
            user.user_type === "rider"
              ? "This account has been converted into a Rider account. Please use Rider Login."
              : "This is a User account. Please use User Login.",
        });
      }

      // 7. Rider approval check
      if (
        user_type === "rider" &&
        user.is_rider_approved !== true
      ) {
        return res.status(403).json({
          status: "rider_not_approved",
          message: "Your rider account is not approved.",
        });
      }

      // 8. Generate JWT
      const token = jwt.sign(
    {
      id: user._id,
      role: user.user_type,
      token_version: user.token_version ?? 0,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

      // 9. Return safe user information only
      const safeUser = {
        _id: user._id,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        phone: user.phone || "",
        user_type: user.user_type,
        auth_provider: user.auth_provider,
        profile_image: user.profile_image || "",
        is_verified: user.is_verified,
        is_rider_approved: user.is_rider_approved,
      };

      return res.status(200).json({
        status: "login_success",
        message: "Login successful.",
        token,
        user: safeUser,
      });

    } catch (err) {
      console.error("Login error:", err);

      return res.status(500).json({
        status: "error",
        message: "Unable to log in. Please try again.",
      });
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


app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. Validate input
    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !username.trim() ||
      !password
    ) {
      return res.status(400).json({
        status: "missing_fields",
        message: "Username and password are required",
      });
    }

    // 2. Check JWT secret
    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is missing in environment variables");

      return res.status(500).json({
        status: "server_configuration_error",
        message: "Server configuration error",
      });
    }

    // 3. Find admin and explicitly retrieve password
    const admin = await Admin.findOne({
      username: username.trim(),
    }).select("+password");

    if (!admin) {
      return res.status(401).json({
        status: "invalid_credentials",
        message: "Invalid username or password",
      });
    }

    // 4. Check password hash availability
    if (
      typeof admin.password !== "string" ||
      !/^\$2[aby]\$/.test(admin.password)
    ) {
      console.error(
        "Admin password hash is missing or is not a bcrypt hash:",
        admin._id
      );

      return res.status(500).json({
        status: "password_configuration_error",
        message: "Unable to verify admin credentials",
      });
    }

    // 5. Compare password
    const passwordMatch = await bcrypt.compare(
      password,
      admin.password
    );

    if (!passwordMatch) {
      return res.status(401).json({
        status: "invalid_credentials",
        message: "Invalid username or password",
      });
    }

    // 6. Check account status
    if (!admin.is_active) {
      return res.status(403).json({
        status: "account_inactive",
        message: "Admin account is inactive",
      });
    }

    // 7. Check verification
    if (!admin.is_verified) {
      return res.status(403).json({
        status: "otp_required",
        message: "Admin verification is required",
        email: admin.email,
      });
    }

    // 8. Validate new role structure
    const allowedRoles = ["gm", "admin"];
    const allowedResponsibilities = [
      "create_promotion",
      "create_rider",
    ];

    if (
      admin.user_type !== "admin" ||
      !allowedRoles.includes(admin.role)
    ) {
      console.error("Invalid admin account role:", {
        id: admin._id,
        user_type: admin.user_type,
        role: admin.role,
      });

      return res.status(403).json({
        status: "invalid_admin_role",
        message: "Administrator account configuration is invalid",
      });
    }

    const responsibilities = Array.isArray(admin.responsibilities)
      ? admin.responsibilities
      : [];

    const hasInvalidResponsibilities = responsibilities.some(
      (item) => !allowedResponsibilities.includes(item)
    );

    if (
      hasInvalidResponsibilities ||
      new Set(responsibilities).size !== responsibilities.length
    ) {
      return res.status(403).json({
        status: "invalid_responsibilities",
        message: "Administrator responsibilities are invalid",
      });
    }

    // GM receives all responsibilities automatically.
    // Admin must have at least one assigned responsibility.
    if (
      (admin.role === "gm" && responsibilities.length > 0) ||
      (admin.role === "admin" && responsibilities.length === 0)
    ) {
      return res.status(403).json({
        status: "invalid_responsibilities",
        message: "Administrator responsibilities are not configured correctly",
      });
    }

    // 9. Generate JWT token using the NEW schema
    const token = jwt.sign(
      {
        id: admin._id.toString(),
        admin: true,
        user_type: "admin",
        role: admin.role,
        responsibilities,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    // 10. Construct admin response using the NEW schema
    const adminData = {
      id: admin._id.toString(),
      username: admin.username,
      email: admin.email,
      first_name: admin.first_name,
      last_name: admin.last_name,
      phone: admin.phone,
      profile_image: admin.profile_image || "",

      user_type: "admin",
      role: admin.role,
      responsibilities,

      must_change_password: admin.must_change_password,

      is_verified: admin.is_verified,
      is_active: admin.is_active,
    };

    // 11. Successful login
    return res.status(200).json({
      status: "login_success",
      message: "Admin login successful",
      token,
      admin: adminData,
    });

  } catch (error) {
    console.error("Admin login error:", error);

    return res.status(500).json({
      status: "error",
      message: "Server error during admin login",
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
    ONLY GENERAL MANAGER CAN CREATE ADMIN ACCOUNTS
  ================================================= */

  app.post(
    "/admin/create-admin",
    requireAdmin,
    async (req, res) => {
      let newAdmin = null;

      try {
        // ============================================
        // 1. VERIFY GENERAL MANAGER
        // ============================================
        if (!req.admin || req.admin.role !== "gm") {
          return res.status(403).json({
            status: "permission_denied",
            message: "Only the General Manager can create admin accounts.",
          });
        }

        // ============================================
        // 2. GET REQUEST BODY
        // ============================================

        const {
          username,
          email,
          first_name,
          last_name,
          phone,
          role,
          responsibilities = [],
        } = req.body;

        // ============================================
        // 3. VALIDATE REQUIRED FIELDS
        // ============================================

        if (
          typeof username !== "string" ||
          typeof email !== "string" ||
          typeof first_name !== "string" ||
          typeof last_name !== "string" ||
          typeof phone !== "string" ||
          !username.trim() ||
          !email.trim() ||
          !first_name.trim() ||
          !last_name.trim() ||
          !phone.trim()
        ) {
          return res.status(400).json({
            status: "missing_fields",
            message: "Please provide all required personal information.",
          });
        }

        // ============================================
        // 4. VALIDATE ACCOUNT ROLE
        // ============================================

        if (!ALLOWED_ADMIN_ROLES.includes(role)) {
          return res.status(400).json({
            status: "invalid_role",
            message: "Select a valid account role.",
          });
        }

        // ============================================
        // 5. VALIDATE RESPONSIBILITIES
        // ============================================

        if (!Array.isArray(responsibilities)) {
          return res.status(400).json({
            status: "invalid_responsibilities",
            message: "Responsibilities must be an array.",
          });
        }

        const uniqueResponsibilities = [
          ...new Set(responsibilities),
        ];

        if (
          uniqueResponsibilities.length !== responsibilities.length ||
          uniqueResponsibilities.some(
            (item) => !ALLOWED_RESPONSIBILITIES.includes(item)
          )
        ) {
          return res.status(400).json({
            status: "invalid_responsibilities",
            message: "One or more responsibilities are invalid.",
          });
        }

        // GM gets all responsibilities automatically.
        if (
          role === "gm" &&
          uniqueResponsibilities.length > 0
        ) {
          return res.status(400).json({
            status: "invalid_responsibilities",
            message: "GM receives all responsibilities automatically.",
          });
        }

        // Admin must receive at least one responsibility.
        if (
          role === "admin" &&
          uniqueResponsibilities.length === 0
        ) {
          return res.status(400).json({
            status: "missing_responsibilities",
            message: "Assign at least one responsibility to this admin.",
          });
        }

        // ============================================
        // 6. NORMALIZE INPUT
        // ============================================

        const normalizedUsername = username.trim();
        const normalizedEmail = email.trim().toLowerCase();
        const normalizedFirstName = first_name.trim();
        const normalizedLastName = last_name.trim();
        const normalizedPhone = phone.trim();

        // ============================================
        // 7. VALIDATE EMAIL
        // ============================================

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(normalizedEmail)) {
          return res.status(400).json({
            status: "invalid_email",
            message: "Please enter a valid email address.",
          });
        }

        // ============================================
        // 8. VALIDATE PHONE
        // ============================================

        const normalizedPhoneDigits = normalizedPhone.replace(
          /[\s()-]/g,
          ""
        );

        if (!/^\+?\d{10,15}$/.test(normalizedPhoneDigits)) {
          return res.status(400).json({
            status: "invalid_phone",
            message: "Please enter a valid phone number.",
          });
        }

        // ============================================
        // 9. CHECK DUPLICATE ACCOUNTS
        // ============================================

        const existingAdmin = await Admin.findOne({
          $or: [
            { username: normalizedUsername },
            { email: normalizedEmail },
            { phone: normalizedPhone },
          ],
        });

        if (existingAdmin) {
          let message = "An administrator account already exists.";

          if (existingAdmin.username === normalizedUsername) {
            message = "Username already exists.";
          } else if (existingAdmin.email === normalizedEmail) {
            message = "Email address already exists.";
          } else if (existingAdmin.phone === normalizedPhone) {
            message = "Phone number already exists.";
          }

          return res.status(409).json({
            status: "admin_exists",
            message,
          });
        }

        // ============================================
        // 10. GENERATE TEMPORARY PASSWORD
        // ============================================

        const temporaryPassword = crypto
          .randomBytes(18)
          .toString("base64url");

        // ============================================
        // 11. HASH PASSWORD
        // ============================================

        const hashedPassword = await bcrypt.hash(
          temporaryPassword,
          12
        );

        // ============================================
        // 12. CREATE ADMIN ACCOUNT
        // ============================================

        newAdmin = await Admin.create({
          username: normalizedUsername,
          email: normalizedEmail,
          first_name: normalizedFirstName,
          last_name: normalizedLastName,
          phone: normalizedPhone,

          password: hashedPassword,

          user_type: "admin",
          role: role,

          responsibilities:
            role === "gm"
              ? []
              : uniqueResponsibilities,

          profile_image: "",

          must_change_password: true,
          is_verified: true,
          is_active: true,

          otp: null,
          otp_expiry: null,
        });

        // ============================================
        // 13. PREPARE RESPONSIBILITY NAMES
        // ============================================

        const responsibilityNames = {
          create_promotion: "Create Promotion",
          create_rider: "Create Rider",
        };

        const assignedResponsibilities =
          role === "gm"
            ? ["All DWJD responsibilities"]
            : uniqueResponsibilities.map(
                (item) => responsibilityNames[item]
              );

        // ============================================
        // 14. SEND LOGIN CREDENTIALS
        // ============================================

        try {
          await sendEmail({
            to: normalizedEmail,

            subject: "Your DWJD Admin Account Credentials",

            html: `
              <!DOCTYPE html>
              <html>
                <body style="
                  font-family: Arial, sans-serif;
                  padding: 24px;
                  color: #1e293b;
                ">

                  <h2>Welcome to DWJD Administration</h2>

                  <p>Hello ${escapeHtml(normalizedFirstName)},</p>

                  <p>
                    Your DWJD administrator account has been
                    created successfully.
                  </p>

                  <p>
                    <strong>Username:</strong>
                    ${escapeHtml(normalizedUsername)}
                  </p>

                  <p>
                    <strong>Temporary Password:</strong>
                    ${escapeHtml(temporaryPassword)}
                  </p>

                  <p>
                    <strong>Account Role:</strong>
                    ${escapeHtml(role.toUpperCase())}
                  </p>

                  <p>
                    <strong>Assigned Responsibilities:</strong>
                    ${assignedResponsibilities
                      .map(escapeHtml)
                      .join(", ")}
                  </p>

                  <p>
                    Please log in using these credentials
                    and change your temporary password immediately.
                  </p>

                  <p>
                    Regards,<br />
                    DWJD Team
                  </p>

                </body>
              </html>
            `,
          });

        } catch (emailError) {
          console.error(
            "Admin credentials email failed:",
            emailError
          );

          // Remove account if credentials could not be sent.
          await Admin.deleteOne({
            _id: newAdmin._id,
          });

          return res.status(502).json({
            status: "email_failed",
            message:
              "The credentials email could not be sent. The admin account was not created. Please try again.",
            email_sent: false,
          });
        }

        // ============================================
        // 15. SUCCESS RESPONSE
        // ============================================

        return res.status(201).json({
          status: "admin_created",

          message:
            "Admin account created and credentials sent successfully.",

          email_sent: true,

          admin: {
            id: newAdmin._id,
            username: newAdmin.username,
            email: newAdmin.email,
            first_name: newAdmin.first_name,
            last_name: newAdmin.last_name,

            role: newAdmin.role,

            responsibilities: newAdmin.responsibilities,

            must_change_password:
              newAdmin.must_change_password,

            is_active: newAdmin.is_active,
            is_verified: newAdmin.is_verified,
          },
        });

      } catch (error) {
        console.error("Create admin error:", error);

        // ============================================
        // 16. DUPLICATE KEY ERROR
        // ============================================

        if (error.code === 11000) {
          return res.status(409).json({
            status: "admin_exists",
            message:
              "Username, email, or phone number already exists.",
          });
        }

        // ============================================
        // 17. MONGOOSE VALIDATION ERROR
        // ============================================

        if (error.name === "ValidationError") {
          return res.status(400).json({
            status: "validation_error",
            message: error.message,
          });
        }

        // ============================================
        // 18. SERVER ERROR
        // ============================================

        return res.status(500).json({
          status: "error",
          message: "Unable to create admin account.",
        });
      }
    }
  );


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

  
// ============================================
// RIDER MANAGEMENT AUTHORIZATION
// GM: Full access automatically
// ADMIN: Requires create_rider responsibility
// ============================================

const requireRiderManagementAccess = async (req, res, next) => {
  try {
    // 1. Check authorization header
    const authorization = req.headers.authorization;

    if (!authorization?.startsWith("Bearer ")) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Please log in as an administrator.",
      });
    }

    // 2. Extract token
    const token = authorization.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Authentication token is missing.",
      });
    }

    // 3. Verify JWT
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

    // 4. Fetch current admin from MongoDB
    const admin = await Admin.findById(decoded.id)
      .select("-password -otp -otp_expiry")
      .lean();

    if (!admin) {
      return res.status(401).json({
        status: "unauthorized",
        message: "Administrator account not found.",
      });
    }

    // 5. Check account status
    if (!admin.is_active) {
      return res.status(403).json({
        status: "forbidden",
        message: "Your administrator account is inactive.",
      });
    }

    if (!admin.is_verified) {
      return res.status(403).json({
        status: "forbidden",
        message: "Your administrator account is not verified.",
      });
    }

    // 6. Read NEW role and responsibilities
    const role = String(admin.role || "").toLowerCase();

    const responsibilities = Array.isArray(admin.responsibilities)
      ? admin.responsibilities
      : [];

    // 7. Check permissions
    // GM automatically has full access.
    const isGM = role === "gm";

    // Normal Admin needs create_rider responsibility.
    const canManageRiders =
      role === "admin" &&
      responsibilities.includes("create_rider");

    if (!isGM && !canManageRiders) {
      return res.status(403).json({
        status: "forbidden",
        message: "You do not have permission to manage rider requests.",
      });
    }

    // 8. Store authenticated administrator details
    req.riderManager = {
      id: String(admin._id),
      username: admin.username,
      user_type: admin.user_type,
      role: admin.role,
      responsibilities,
    };

    console.log("========== RIDER MANAGEMENT ACCESS ==========");
    console.log("Admin:", admin.username);
    console.log("Role:", role);
    console.log("Responsibilities:", responsibilities);
    console.log("Access granted:", true);

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

        // 1. Validate request ID
        if (!mongoose.Types.ObjectId.isValid(requestId)) {
          return res.status(400).json({
            status: "error",
            message: "Invalid rider request ID.",
          });
        }

        // 2. Validate status
        if (!["approved", "rejected"].includes(status)) {
          return res.status(400).json({
            status: "error",
            message: "Status must be approved or rejected.",
          });
        }

        // 3. Validate rejection reason
        if (
          status === "rejected" &&
          !String(rejection_reason || "").trim()
        ) {
          return res.status(400).json({
            status: "error",
            message: "Please provide a reason for rejection.",
          });
        }

        // 4. Update application
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
            returnDocument: "after",
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
            message: `This request cannot be reviewed because its current status is "${existingRequest.status}".`,
          });
        }

        // 5. Send rejection email only
        let emailSent = null;

        if (status === "rejected") {
          emailSent = false;

          try {
            const applicantName =
              `${updatedRequest.first_name || ""} ${
                updatedRequest.last_name || ""
              }`.trim() || "Applicant";

            const safeName = escapeHtml(applicantName);
            const safeReason = escapeHtml(
              updatedRequest.rejection_reason
            );

            await sendEmail({
              to: updatedRequest.email,

              subject: "Update on Your DWJD Rider Application",

              html: `
                <!DOCTYPE html>
                <html>
                  <body style="
                    margin: 0;
                    padding: 25px;
                    background: #f4f6f8;
                    font-family: Arial, sans-serif;
                  ">
                    <div style="
                      max-width: 600px;
                      margin: auto;
                      background: white;
                      border-radius: 12px;
                      overflow: hidden;
                      border: 1px solid #e5e7eb;
                    ">
                      <div style="
                        background: #111827;
                        color: white;
                        padding: 25px;
                        text-align: center;
                      ">
                        <h1>DWJD</h1>
                        <p>Rider Application Update</p>
                      </div>

                      <div style="padding: 30px;">
                        <h2>Hello ${safeName},</h2>

                        <p>
                          Thank you for your interest in becoming
                          a DWJD rider.
                        </p>

                        <p>
                          After reviewing your application,
                          we regret to inform you that your
                          application has been rejected.
                        </p>

                        <div style="
                          background: #fef2f2;
                          border-left: 4px solid #dc2626;
                          padding: 16px;
                          margin: 20px 0;
                        ">
                          <h3 style="color: #b91c1c;">
                            Reason for rejection
                          </h3>

                          <p style="
                            color: #374151;
                            line-height: 1.6;
                          ">
                            ${safeReason}
                          </p>
                        </div>

                        <p>
                          Thank you for considering DWJD.
                          We appreciate your interest and
                          wish you the best.
                        </p>

                        <p>
                          Regards,<br />
                          <strong>DWJD Customer Support Team</strong>
                        </p>
                      </div>

                      <div style="
                        background: #f9fafb;
                        padding: 15px;
                        text-align: center;
                        color: #6b7280;
                        font-size: 12px;
                      ">
                        This is an automated email from DWJD.
                      </div>
                    </div>
                  </body>
                </html>
              `,
            });

            emailSent = true;

            console.log(
              "Rider rejection email sent:",
              updatedRequest.email
            );
          } catch (emailError) {
            console.error(
              "Rider rejection email failed:",
              emailError.response?.data || emailError.message
            );
          }
        }

        // 6. Return success even if email delivery fails
        return res.status(200).json({
          status: "success",
          message:
            status === "approved"
              ? "Rider request approved successfully."
              : emailSent
                ? "Rider request rejected and rejection email sent successfully."
                : "Rider request rejected, but the rejection email could not be sent.",

          email_sent: emailSent,
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
    const existingRider = await User.findById(
      riderRequest.created_user_id
    ).select(
      "_id username email first_name last_name user_type"
    );

    if (!existingRider) {
      return res.status(409).json({
        status: "error",
        message:
          "The application is marked as created, but the rider account could not be found.",
      });
    }

    return res.status(200).json({
      status: "rider_created",
      message: "Rider account was already created successfully.",
      rider: {
        id: existingRider._id,
        username: existingRider.username,
        email: existingRider.email,
        first_name: existingRider.first_name,
        last_name: existingRider.last_name,
        user_type: existingRider.user_type,
      },
      request: {
        id: riderRequest._id,
        status: riderRequest.status,
      },
      email_sent: null,
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

  // ============================================
  // EXISTING USER: CONVERT TO RIDER
  // ============================================

  if (existingUser) {

    // Only normal user accounts can be converted.
    if (existingUser.user_type !== "user") {
      return res.status(409).json({
        status: "error",
        message:
          "This account cannot be converted into a rider account.",
      });
    }

    const session = await mongoose.startSession();

    let convertedUser;
    let updatedRequest;

    try {

      // Update the user and application together.
      await session.withTransaction(async () => {

        convertedUser = await User.findOneAndUpdate(
    {
      _id: existingUser._id,
      user_type: "user",
    },
    {
      $set: {
        user_type: "rider",
        is_rider_approved: true,
      },
      $inc: {
        token_version: 1,
      },
    },
    {
      returnDocument: "after",
      runValidators: true,
      session,
    }
  );

        if (!convertedUser) {
          throw new Error("USER_CONVERSION_FAILED");
        }

        updatedRequest = await BecomeRider.findOneAndUpdate(
          {
            _id: riderRequest._id,
            status: "approved",
            created_user_id: null,
          },
          {
            $set: {
              status: "account_created",
              created_user_id: convertedUser._id,
              account_created_at: new Date(),
            },
          },
          { 
    returnDocument: "after",
    runValidators: true,
    session,
  }
        );

        if (!updatedRequest) {
          throw new Error("RIDER_REQUEST_CHANGED");
        }

      });

    } catch (conversionError) {

      console.error(
        "Existing user rider conversion failed:",
        conversionError
      );

      if (
        conversionError.message === "USER_CONVERSION_FAILED" ||
        conversionError.message === "RIDER_REQUEST_CHANGED"
      ) {
        return res.status(409).json({
          status: "error",
          message:
            "The account or application changed. Please refresh and try again.",
        });
      }

      throw conversionError;

    } finally {
      await session.endSession();
    }

    // ============================================
    // SEND ACCOUNT CONVERSION EMAIL
    // ============================================

    let emailSent = false;

    try {

      await sendEmail({
        to: email,

        subject: "DWJD - Your Existing Account Is Now a Rider Account",

        html: `
          <div style="
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: auto;
            padding: 25px;
            color: #1e293b;
          ">

            <h2>Hello ${escapeHtml(convertedUser.first_name)},</h2>

            <p>
              Great news! Your DWJD rider application has
              been approved.
            </p>

            <p>
              Your existing DWJD account has successfully
              been converted into a Rider account.
            </p>

            <div style="
              background: #ecfdf5;
              padding: 18px;
              border-radius: 10px;
              margin: 20px 0;
            ">
              <h3 style="color: #047857;">
                Account Conversion Successful
              </h3>

              <p>
                <strong>Username:</strong>
                ${escapeHtml(convertedUser.username)}
              </p>

              <p>
                <strong>Account Type:</strong> Rider
              </p>
            </div>

            <p>
              You can now log in through the DWJD Rider Login
              using your existing login credentials or Google
              sign-in.
            </p>

            <p>
              Your existing account information and login
              details have been preserved.
            </p>

            <p>
              Welcome to the DWJD Rider Community!
            </p>

            <p>
              Regards,<br />
              <strong>DWJD Team</strong>
            </p>

          </div>
        `,
      });

      emailSent = true;

    } catch (emailError) {

      console.error(
        "Rider conversion email failed:",
        emailError.message
      );

    }

    // ============================================
    // EXISTING USER CONVERSION RESPONSE
    // ============================================

    return res.status(200).json({

      status: emailSent
        ? "existing_user_converted"
        : "existing_user_converted_email_failed",

      message: emailSent
        ? "Existing user account successfully converted into a rider account. Notification email sent."
        : "Account converted successfully, but notification email could not be sent.",

      email_sent: emailSent,

      rider: {
        id: convertedUser._id,
        username: convertedUser.username,
        email: convertedUser.email,
        first_name: convertedUser.first_name,
        last_name: convertedUser.last_name,
        user_type: convertedUser.user_type,
      },

      request: {
        id: updatedRequest._id,
        status: updatedRequest.status,
      },

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


  /* =====================================================
    API: SUBMIT ADVERTISEMENT / PROMOTION REQUEST
    POST /advertisements/request

    Features:
    1. Upload banner and video to Google Drive
    2. Save Google Drive file IDs in MongoDB
    3. Save campaign details
    4. Send confirmation email
    5. Roll back uploaded files if saving fails
    6. Preserve media cleanup tracking
  ===================================================== */

  app.post(
    "/advertisements/request",

    // 1. Handle multipart form uploads
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
        // 2. Read form data
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

        // 3. Validate required fields
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

        // 4. Validate email
        const email = String(contact_email)
          .trim()
          .toLowerCase();

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return res.status(400).json({
            status: "error",
            message: "Please enter a valid business email.",
          });
        }

        // 5. Validate promotion type
        const allowedPromotionTypes = [
          "banner",
          "sponsored_post",
          "video",
          "product_promotion",
          "brand_awareness",
        ];

        if (!allowedPromotionTypes.includes(promotion_type)) {
          return res.status(400).json({
            status: "error",
            message: "Invalid promotion type.",
          });
        }

        // 6. Validate placement
        const allowedPlacements = [
          "home_page",
          "donation_page",
          "pickup_page",
          "rider_dashboard",
          "all_pages",
        ];

        const selectedPlacement = placement || "home_page";

        if (!allowedPlacements.includes(selectedPlacement)) {
          return res.status(400).json({
            status: "error",
            message: "Invalid advertisement placement.",
          });
        }

        // 7. Validate collaboration type
        const allowedCollaborationTypes = [
          "paid_promotion",
          "sponsorship",
          "brand_partnership",
        ];

        const selectedCollaboration =
          collaboration_type || "paid_promotion";

        if (!allowedCollaborationTypes.includes(selectedCollaboration)) {
          return res.status(400).json({
            status: "error",
            message: "Invalid collaboration type.",
          });
        }

        // 8. Validate budget
        const budget = Number(amount_paid);

        if (!Number.isFinite(budget) || budget < 0) {
          return res.status(400).json({
            status: "error",
            message: "Budget must be a valid non-negative number.",
          });
        }

        // 9. Validate campaign dates
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

        // 10. Read uploaded files
        const banner = req.files?.banner?.[0] || null;
        const video = req.files?.video?.[0] || null;

        // 11. Upload media to Google Drive
        let imageUploadResult = null;
        let videoUploadResult = null;

        if (banner) {
          imageUploadResult = await uploadPromotionFileToDrive(
            banner,
            title
          );

          uploadedFileIds.push(imageUploadResult.fileId);
        }

        if (video) {
          videoUploadResult = await uploadPromotionFileToDrive(
            video,
            title
          );

          uploadedFileIds.push(videoUploadResult.fileId);
        }

        // 12. Prepare optional fields
        const companyWebsite = company_website
          ? String(company_website).trim()
          : "";

        const destinationUrl = target_url
          ? String(target_url).trim()
          : "";

        // 13. Save campaign in MongoDB
        const advertisement = await Advertisement.create({
          // Brand / Company information
          brand_name: String(brand_name).trim(),
          company_name: String(company_name).trim(),
          contact_person: String(contact_person).trim(),
          contact_email: email,
          contact_phone: String(contact_phone).trim(),
          company_website: companyWebsite,

          // Advertisement details
          title: String(title).trim(),
          description: String(description).trim(),
          promotion_type,

          // Google Drive media URLs
          image_url: imageUploadResult?.url || "",
          video_url: videoUploadResult?.url || "",

          // Google Drive file IDs
          image_drive_file_id: imageUploadResult?.fileId || "",
          video_drive_file_id: videoUploadResult?.fileId || "",

          target_url: destinationUrl,

          // Placement
          placement: selectedPlacement,

          // Campaign schedule
          start_date: startDate,
          end_date: endDate,

          // Payment
          amount_paid: budget,
          currency: "INR",
          payment_status: "pending",
          payment_reference: "",
          payment_paid_at: null,

          // Collaboration
          collaboration_type: selectedCollaboration,

          // Approval
          status: "pending",
          rejection_reason: "",
          reviewed_by: null,
          reviewed_at: null,

          // Activation
          is_active: false,

          // Media cleanup tracking
          media_cleanup_status: "pending",
          media_cleanup_attempts: 0,
          media_cleanup_last_attempt_at: null,
          media_cleanup_error: "",
          media_cleaned_at: null,
        });

        // 14. Send confirmation email
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
                  Your request is currently pending review.
                  Submission does not mean the campaign is approved
                  or payment has been received.
                </p>

                <p>Thank you,<br/>DWJD Team</p>
              </div>
            `,
          });

          emailSent = true;
        } catch (emailError) {
          console.error(
            "Promotion confirmation email failed:",
            emailError.message
          );
        }

        // 15. Success response
        return res.status(201).json({
          status: "success",

          message: emailSent
            ? "Promotion request submitted successfully. Check your email for confirmation."
            : "Promotion request saved successfully, but confirmation email could not be sent.",

          email_sent: emailSent,

          advertisement: {
            _id: advertisement._id,

            brand_name: advertisement.brand_name,
            company_name: advertisement.company_name,
            title: advertisement.title,

            promotion_type: advertisement.promotion_type,

            image_url: advertisement.image_url,
            video_url: advertisement.video_url,

            target_url: advertisement.target_url,
            placement: advertisement.placement,

            start_date: advertisement.start_date,
            end_date: advertisement.end_date,

            amount_paid: advertisement.amount_paid,
            currency: advertisement.currency,

            payment_status: advertisement.payment_status,
            status: advertisement.status,
            is_active: advertisement.is_active,

            media_cleanup_status:
              advertisement.media_cleanup_status,

            createdAt: advertisement.createdAt,
          },
        });

      } catch (error) {
        console.error(
          "Promotion submission error:",
          error
        );

        // 16. Roll back uploaded Drive files
        for (const fileId of uploadedFileIds) {
          try {
            await drive.files.delete({
              fileId,
            });
          } catch (cleanupError) {
            console.error(
              "Google Drive rollback failed:",
              fileId,
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

        if (!Number.isFinite(amount) || amount <= 0) {
          return res.status(400).json({
            status: "error",
            message:
              "The promotion does not have a valid GM-approved amount.",
          });
        }

        // 6. This workflow supports INR only.
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

        // 9. Prevent duplicate links.
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

        // 10. Convert INR to paise.
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

        // 11. Create Razorpay Payment Link.
        const paymentLink = await razorpay.paymentLink.create({
          amount: amountInPaise,
          currency: "INR",

          accept_partial: false,

          description: `DWJD promotion payment - ${
            advertisement.brand_name ||
            advertisement.title ||
            "Promotion"
          }`,

          customer: {
            name:
              advertisement.contact_person ||
              advertisement.brand_name ||
              "Promotion Owner",

            email,

            ...(advertisement.contact_phone
              ? {
                  contact: String(
                    advertisement.contact_phone
                  ),
                }
              : {}),
          },

          reference_id: `ad_${advertisement._id}`,

          notes: {
            advertisement_id: String(advertisement._id),

            brand_name: String(
              advertisement.brand_name || ""
            ).slice(0, 256),
          },

          reminder_enable: true,

          // Request the standard payment methods.
          options: {
            checkout: {
              method: {
                card: 1,
                upi: 1,
                netbanking: 1,
                wallet: 1,
              },
            },
          },
        });

        // 12. Save payment details in MongoDB.
        advertisement.payment_link_id = paymentLink.id;
        advertisement.payment_link_url =
          paymentLink.short_url;
        advertisement.payment_link_sent_at = new Date();
        advertisement.payment_status = "pending";
        advertisement.is_active = false;

        await advertisement.save();

        // 13. Escape dynamic values used in the email.
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

        // 14. Send payment link using the existing Brevo helper.
        try {
          await sendEmail({
            to: email,
            subject: "DWJD promotion — payment required",

            html: `
              <!DOCTYPE html>
              <html>
                <body style="
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
                </body>
              </html>
            `,
          });
        } catch (emailError) {
          console.error(
            "Payment link email failed:",
            emailError.message
          );

          // Payment link already exists and is saved.
          // Do not create another link just to retry the email.
          return res.status(502).json({
            status: "partial_success",
            message:
              "Payment link was created and saved, but the email could not be sent. Use the existing link when retrying email delivery.",
            payment_link_id: paymentLink.id,
            payment_link_url: paymentLink.short_url,
            email_sent: false,
            advertisement_id: String(advertisement._id),
          });
        }

        // 15. Return success response.
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

    // 6. Read the verified Razorpay event.
  const event = req.body?.event;

  // Process QR payments using the existing QR handler.
  if (event === "qr_code.credited") {
    return await processPromotionQrCreditedWebhook(req, res);
  }

  // Keep the existing payment-link workflow.
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


  /* =====================================================
    ADMIN API: DEACTIVATE EXPIRED PROMOTIONS
    PATCH /admin/advertisements/deactivate-expired

    1. Deactivate expired campaigns
    2. Delete expired Google Drive photos/videos
    3. Preserve MongoDB campaign history
  ===================================================== */

  app.patch(
    "/admin/advertisements/deactivate-expired",
    requireAdmin,
    async (req, res) => {
      try {
        const result = await cleanupExpiredPromotionMedia();

        return res.status(200).json({
          success: true,
          message: "Expired promotions processed successfully.",

          deactivated: result.deactivated || 0,
          checked: result.checked || 0,
          cleaned: result.cleaned || 0,
          failed: result.failed || 0,
        });

      } catch (error) {
        console.error(
          "Deactivate expired promotions error:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Failed to process expired promotions.",
        });
      }
    }
  );

  /* ============================================
    AUTOMATIC PROMOTION MEDIA CLEANUP
    Runs every 5 minutes
  ============================================ */

  cron.schedule("*/5 * * * *", async () => {
    try {
      console.log("Starting expired promotion cleanup...");

      const result = await cleanupExpiredPromotionMedia();

      console.log("Promotion cleanup completed:", result);
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


  app.patch(
    "/admin/advertisements/cleanup-expired",
    requireAdmin,
    async (req, res) => {
      try {
        console.log("Admin triggered expired promotion cleanup.");

        const cleanupResult = await cleanupExpiredPromotionMedia();

        return res.status(200).json({
          success: true,
          message: "Expired promotion media cleanup completed.",
          data: {
            checked: cleanupResult.checked,
            deactivated: cleanupResult.deactivated,
            cleaned: cleanupResult.cleaned,
            failed: cleanupResult.failed,
            skipped: cleanupResult.skipped,
          },
        });
      } catch (error) {
        console.error("Expired promotion cleanup API error:", error);

        return res.status(500).json({
          success: false,
          message: "Failed to clean expired promotion media.",
          error: error.message,
        });
      }
    }
  );

  // ============================================
  // GET: PROMOTION CLEANUP STATUS
  // ============================================

  app.get(
    "/admin/advertisements/cleanup-status",
    requireAdmin,
    async (req, res) => {
      try {
        const now = new Date();

        const [
          expiredTotal,
          pending,
          processing,
          completed,
          failed,
          failedCampaigns,
        ] = await Promise.all([
          Advertisement.countDocuments({
            end_date: { $lte: now },
          }),

          Advertisement.countDocuments({
            end_date: { $lte: now },
            media_cleanup_status: "pending",
          }),

          Advertisement.countDocuments({
            end_date: { $lte: now },
            media_cleanup_status: "processing",
          }),

          Advertisement.countDocuments({
            end_date: { $lte: now },
            media_cleanup_status: "completed",
          }),

          Advertisement.countDocuments({
            end_date: { $lte: now },
            media_cleanup_status: "failed",
          }),

          Advertisement.find({
            end_date: { $lte: now },
            media_cleanup_status: "failed",
          })
            .select(
              "_id brand_name company_name title end_date image_url video_url image_drive_file_id video_drive_file_id media_cleanup_attempts media_cleanup_last_attempt_at media_cleanup_error"
            )
            .sort({ media_cleanup_last_attempt_at: -1 })
            .limit(100)
            .lean(),
        ]);

        return res.status(200).json({
          success: true,
          message: "Promotion cleanup status fetched successfully.",

          summary: {
            expired_campaigns: expiredTotal,
            pending,
            processing,
            completed,
            failed,
          },

          failed_campaigns: failedCampaigns,
        });
      } catch (error) {
        console.error("Cleanup status API error:", error);

        return res.status(500).json({
          success: false,
          message: "Failed to fetch cleanup status.",
        });
      }
    }
  );



  // ============================================
  // EXPIRED PROMOTION MEDIA CLEANUP
  // ============================================

  const PROMOTION_MEDIA_FOLDER_ID =
    process.env.GOOGLE_DRIVE_ADVERTISEMENTS_FOLDER_ID;

  const CLEANUP_BATCH_SIZE = 50;
  const CLEANUP_LOCK_TIMEOUT_MINUTES = 15;

  // Extract only IDs from supported Google Drive URLs.
  const extractDriveFileId = (url) => {
    if (!url || typeof url !== "string") return null;

    const patterns = [
      /drive\.google\.com\/file\/d\/([a-zA-Z0-9_-]+)/,
      /drive\.google\.com\/uc\?.*id=([a-zA-Z0-9_-]+)/,
      /drive\.google\.com\/open\?.*id=([a-zA-Z0-9_-]+)/,
    ];

    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) return match[1];
    }

    return null;
  };

  // Delete a file only if it belongs to our advertisements folder.
  const deletePromotionDriveFile = async (fileId) => {
    if (!fileId) return;

    if (!PROMOTION_MEDIA_FOLDER_ID) {
      throw new Error("Google Drive advertisements folder ID is missing.");
    }

    try {
      const file = await drive.files.get({
        fileId,
        fields: "id, parents, trashed",
      });

      // Already in trash: treat it as successfully removed.
      if (file.data.trashed) return;

      const belongsToPromotionFolder =
        file.data.parents?.includes(PROMOTION_MEDIA_FOLDER_ID);

      if (!belongsToPromotionFolder) {
        throw new Error(
          `File ${fileId} does not belong to the advertisements folder.`
        );
      }

      await drive.files.delete({ fileId });

      console.log(`Deleted promotion media from Drive: ${fileId}`);
    } catch (error) {
      // A 404 means the file has already been deleted.
      if (error.code === 404 || error.response?.status === 404) {
        console.log(`Drive file already deleted: ${fileId}`);
        return;
      }

      throw error;
    }
  };

  // ============================================
  // MAIN CLEANUP FUNCTION
  // ============================================

  const cleanupExpiredPromotionMedia = async () => {
    const now = new Date();

    const staleLockTime = new Date(
      now.getTime() - CLEANUP_LOCK_TIMEOUT_MINUTES * 60 * 1000
    );

    const result = {
      checked: 0,
      deactivated: 0,
      cleaned: 0,
      failed: 0,
      skipped: 0,
    };

    // 1. Deactivate every expired active promotion.
    const deactivationResult = await Advertisement.updateMany(
      {
        is_active: true,
        end_date: { $lte: now },
      },
      {
        $set: { is_active: false },
      }
    );

    result.deactivated = deactivationResult.modifiedCount || 0;

    // 2. Find expired campaigns that have media to clean.
    const mediaExists = {
      $or: [
        { image_drive_file_id: { $nin: ["", null] } },
        { video_drive_file_id: { $nin: ["", null] } },
        { image_url: { $nin: ["", null] } },
        { video_url: { $nin: ["", null] } },
      ],
    };

    const retryableStatus = {
      $or: [
        { media_cleanup_status: "pending" },
        { media_cleanup_status: "failed" },
        { media_cleanup_status: { $exists: false } },
        {
          media_cleanup_status: "processing",
          media_cleanup_last_attempt_at: { $lte: staleLockTime },
        },
        {
          media_cleanup_status: "processing",
          media_cleanup_last_attempt_at: null,
        },
      ],
    };

    const candidates = await Advertisement.find({
      end_date: { $lte: now },
      $and: [mediaExists, retryableStatus],
    })
      .select(
        "_id image_url video_url image_drive_file_id video_drive_file_id"
      )
      .limit(CLEANUP_BATCH_SIZE)
      .lean();

    result.checked = candidates.length;

    // 3. Process campaigns individually.
    for (const candidate of candidates) {
      let claimedAdvertisement;

      try {
        // Atomic claim prevents two workers from cleaning the same campaign.
        claimedAdvertisement = await Advertisement.findOneAndUpdate(
          {
            _id: candidate._id,
            end_date: { $lte: now },
            $and: [mediaExists, retryableStatus],
          },
          {
            $set: {
              media_cleanup_status: "processing",
              media_cleanup_last_attempt_at: now,
              media_cleanup_error: "",
            },
            $inc: {
              media_cleanup_attempts: 1,
            },
          },
          { new: true }
        );

        if (!claimedAdvertisement) {
          result.skipped++;
          continue;
        }

        const ad = claimedAdvertisement;

        // Prefer stored Drive IDs; fall back to supported Drive URLs.
        const imageFileId =
          ad.image_drive_file_id || extractDriveFileId(ad.image_url);

        const videoFileId =
          ad.video_drive_file_id || extractDriveFileId(ad.video_url);

        // Do not silently clear a media URL if we cannot identify its Drive file.
        if (ad.image_url && !imageFileId) {
          throw new Error("Could not identify the image Drive file ID.");
        }

        if (ad.video_url && !videoFileId) {
          throw new Error("Could not identify the video Drive file ID.");
        }

        // Delete unique IDs only once.
        const fileIds = [...new Set([imageFileId, videoFileId].filter(Boolean))];

        for (const fileId of fileIds) {
          await deletePromotionDriveFile(fileId);
        }

        // 4. Clear references only after all Drive deletions succeed.
        await Advertisement.updateOne(
          {
            _id: ad._id,
            media_cleanup_status: "processing",
          },
          {
            $set: {
              image_url: "",
              video_url: "",
              image_drive_file_id: "",
              video_drive_file_id: "",
              media_cleanup_status: "completed",
              media_cleanup_error: "",
              media_cleaned_at: new Date(),
              is_active: false,
            },
          }
        );

        result.cleaned++;

        console.log(`Promotion media cleanup completed: ${ad._id}`);
      } catch (error) {
        result.failed++;

        console.error(
          `Promotion media cleanup failed (${candidate._id}):`,
          error.message
        );

        if (claimedAdvertisement) {
          await Advertisement.updateOne(
            {
              _id: candidate._id,
              media_cleanup_status: "processing",
            },
            {
              $set: {
                media_cleanup_status: "failed",
                media_cleanup_error: error.message,
                is_active: false,
              },
            }
          );
        }
      }
    }

    console.log("Expired promotion cleanup result:", result);

    return result;
  };
  const OAUTH_STATE_SECRET = process.env.GOOGLE_OAUTH_STATE_SECRET;

  if (!OAUTH_STATE_SECRET) {
    throw new Error("GOOGLE_OAUTH_STATE_SECRET is missing");
  }

  const createOAuthState = (userType) => {
    const payload = {
      user_type: userType,
      nonce: crypto.randomBytes(32).toString("hex"),
      created_at: Date.now(),
    };

    const encodedPayload = Buffer
      .from(JSON.stringify(payload))
      .toString("base64url");

    const signature = crypto
      .createHmac("sha256", OAUTH_STATE_SECRET)
      .update(encodedPayload)
      .digest("base64url");

    return {
      state: `${encodedPayload}.${signature}`,
      nonce: payload.nonce,
    };
  };

  const verifyOAuthState = (state) => {
    try {
      const [encodedPayload, receivedSignature] = state.split(".");

      if (!encodedPayload || !receivedSignature) {
        return null;
      }

      const expectedSignature = crypto
        .createHmac("sha256", OAUTH_STATE_SECRET)
        .update(encodedPayload)
        .digest();

      const actualSignature = Buffer.from(
        receivedSignature,
        "base64url"
      );

      if (
        actualSignature.length !== expectedSignature.length ||
        !crypto.timingSafeEqual(actualSignature, expectedSignature)
      ) {
        return null;
      }

      const payload = JSON.parse(
        Buffer.from(encodedPayload, "base64url").toString()
      );

      if (
        !["user", "rider"].includes(payload.user_type) ||
        !payload.nonce ||
        Date.now() - payload.created_at > 10 * 60 * 1000 ||
        Date.now() < payload.created_at
      ) {
        return null;
      }

      return payload;
    } catch (error) {
      return null;
    }
  };
  // Generate a unique username for Google signup
  const generateGoogleUsername = async (email) => {
    const baseUsername = email
      .split("@")[0]
      .replace(/[^a-zA-Z0-9_]/g, "")
      .slice(0, 15) || "googleuser";

    let username;
    let exists = true;

    while (exists) {
      const randomNumber = crypto.randomInt(100000, 999999);
      username = `${baseUsername}_${randomNumber}`;

      exists = await User.exists({ username });
    }

    return username;
  };

  // Hash the temporary login code
  const hashOAuthCode = (code) => {
    return crypto
      .createHash("sha256")
      .update(code)
      .digest("hex");
  };

  // ========================================
  // GOOGLE OAUTH - START LOGIN
  // GET /auth/google?user_type=user
  // GET /auth/google?user_type=rider
  // ========================================

  app.get("/auth/google", (req, res) => {
    try {
      const { user_type } = req.query;

      // Validate requested account type
      if (!["user", "rider"].includes(user_type)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid user type. Use user or rider.",
        });
      }

      // Generate signed OAuth state
      const { state, nonce } = createOAuthState(user_type);

      // Store nonce in a secure browser cookie.
      // The callback API will compare it with the signed state.
      res.cookie("dwjd_oauth_state", nonce, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 10 * 60 * 1000,
        path: "/",
      });

      // Generate Google authorization URL
      const googleAuthUrl = googleOAuthClient.generateAuthUrl({
        access_type: "online",
        scope: [
          "openid",
          "email",
          "profile",
        ],
        state,
        prompt: "select_account",
      });

      // Redirect browser to Google
      return res.redirect(googleAuthUrl);

    } catch (error) {
      console.error("Google OAuth start error:", error);

      return res.status(500).json({
        status: "error",
        message: "Unable to start Google authentication.",
      });
    }
  });
  // ======================================================
  // API 2: GOOGLE OAUTH CALLBACK
  // GET /oauth2callback
  // ======================================================

  app.get("/oauth2callback", async (req, res) => {
    try {
      const { code, state, error } = req.query;

      const frontendURL = process.env.FRONTEND_URL;

      if (!frontendURL) {
        throw new Error("FRONTEND_URL is not configured");
      }

      const redirectWithError = (errorCode) => {
        res.clearCookie("dwjd_oauth_state", {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          path: "/",
        });

        return res.redirect(
          `${frontendURL}/login?google_error=${encodeURIComponent(errorCode)}`
        );
      };

      // 1. Check whether Google returned an error
      if (error) {
        return redirectWithError("cancelled");
      }

      if (!code || !state || typeof code !== "string" ||
          typeof state !== "string") {
        return redirectWithError("authentication_failed");
      }

      // 2. Verify signed OAuth state
      const statePayload = verifyOAuthState(state);

      if (!statePayload) {
        return redirectWithError("invalid_state");
      }

      // 3. Verify browser-bound nonce
      const browserNonce = req.cookies?.dwjd_oauth_state;

      if (
        !browserNonce ||
        browserNonce !== statePayload.nonce
      ) {
        return redirectWithError("invalid_state");
      }

      res.clearCookie("dwjd_oauth_state", {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
      });

      const requestedUserType = statePayload.user_type;

      // 4. Exchange authorization code with Google
      const { tokens } = await googleOAuthClient.getToken(code);

      if (!tokens.id_token) {
        return redirectWithError("verification_failed");
      }

      // 5. Verify Google's ID token
      const ticket = await googleOAuthClient.verifyIdToken({
        idToken: tokens.id_token,
        audience: process.env.GOOGLE_OAUTH_CLIENT_ID,
      });

      const googlePayload = ticket.getPayload();

      if (
        !googlePayload ||
        !googlePayload.email ||
        googlePayload.email_verified !== true ||
        !googlePayload.sub
      ) {
        return redirectWithError("verification_failed");
      }

      const googleId = googlePayload.sub;
      const email = googlePayload.email.toLowerCase().trim();

      const firstName = googlePayload.given_name || "Google";
      const lastName = googlePayload.family_name || "User";
      const profileImage = googlePayload.picture || "";

      // 6. Find account using Google ID first
      let user = await User.findOne({
        google_id: googleId,
      });

      if (user) {
        // Existing Google-linked account must have the requested role
        if (user.user_type !== requestedUserType) {
          return redirectWithError("account_type_mismatch");
        }

        if (user.email.toLowerCase() !== email) {
          return redirectWithError("account_conflict");
        }
      } else {
        // 7. Check whether an account already exists with this email
        user = await User.findOne({ email });

        if (user) {
          // Never silently change an existing account's role
          if (user.user_type !== requestedUserType) {
            return redirectWithError("account_type_mismatch");
          }

          // A Google ID already linked to another account is a conflict
          if (user.google_id && user.google_id !== googleId) {
            return redirectWithError("account_conflict");
          }

          // Link verified Google identity to existing account
          user.google_id = googleId;

          // Keep existing local password and auth_provider intact
          if (!user.is_verified) {
            user.is_verified = true;
            user.otp = null;
            user.otp_expiry = null;
          }

          await user.save();
        } else {
          // 8. Create a new DWJD account
          const username = await generateGoogleUsername(email);

          user = await User.create({
            username,
            first_name: firstName,
            last_name: lastName,

            // Google does not provide a phone number.
            // Your User schema must allow this field to be optional.
            email,
            phone: undefined,

            user_type: requestedUserType,
            auth_provider: "google",
            google_id: googleId,

            password: null,
            profile_image: profileImage,

            is_verified: true,

            otp: null,
            otp_expiry: null,

            // Riders must still go through your approval process.
            is_rider_approved:
              requestedUserType === "rider" ? false : undefined,
          });
        }
      }

      // 9. Generate a cryptographically random one-time login code
      const loginCode = crypto.randomBytes(32).toString("hex");

      const codeHash = hashOAuthCode(loginCode);

      // 10. Store only its hash; expires in two minutes
      await OAuthLoginCode.create({
        code_hash: codeHash,
        user_id: user._id,
        expires_at: new Date(Date.now() + 2 * 60 * 1000),
      });

      // 11. Redirect to frontend callback
      return res.redirect(
        `${frontendURL}/auth/callback?code=${encodeURIComponent(loginCode)}`
      );

    } catch (error) {
      console.error("Google OAuth callback error:", error);

      const frontendURL = process.env.FRONTEND_URL;

      if (frontendURL) {
        return res.redirect(
          `${frontendURL}/login?google_error=authentication_failed`
        );
      }

      return res.status(500).send("Google authentication failed.");
    }
  });
  // ======================================================
  // API 3: GOOGLE OAUTH CODE EXCHANGE
  // POST /auth/google/exchange
  // ======================================================


  app.post("/auth/google/exchange", async (req, res) => {
    try {
      const { code } = req.body;

      // 1. Validate Google login code
      if (!code || typeof code !== "string" || code.length !== 64) {
        return res.status(400).json({
          status: "error",
          message: "Invalid or missing authentication code.",
        });
      }

      // 2. Hash the received code
      const codeHash = crypto
        .createHash("sha256")
        .update(code)
        .digest("hex");

      // 3. Consume one-time login code
      const loginCode = await OAuthLoginCode.findOneAndDelete({
        code_hash: codeHash,
        expires_at: { $gt: new Date() },
      });

      if (!loginCode) {
        return res.status(401).json({
          status: "error",
          message: "Authentication code is invalid, expired, or already used.",
        });
      }

      // 4. Find current account role from MongoDB
      const user = await User.findById(loginCode.user_id);

      if (!user) {
        return res.status(404).json({
          status: "error",
          message: "User account not found.",
        });
      }

      // 5. Verify account
      if (!user.is_verified) {
        return res.status(403).json({
          status: "error",
          message: "Your account is not verified.",
        });
      }

      if (!["user", "rider"].includes(user.user_type)) {
        return res.status(403).json({
          status: "error",
          message: "Invalid account role.",
        });
      }

      // 6. Riders must be approved
      if (
        user.user_type === "rider" &&
        user.is_rider_approved !== true
      ) {
        return res.status(403).json({
          status: "rider_not_approved",
          message: "Your rider account is not approved.",
        });
      }

      // 7. Generate JWT using the CURRENT MongoDB role
    const token = jwt.sign(
    {
      id: user._id,
      role: user.user_type,
      token_version: user.token_version ?? 0,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

      // 8. Return safe user details
      const safeUser = {
        _id: user._id,
        username: user.username,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        phone: user.phone || "",
        user_type: user.user_type,
        auth_provider: user.auth_provider,
        profile_image: user.profile_image || "",
        is_verified: user.is_verified,
        is_rider_approved: user.is_rider_approved,
      };

      return res.status(200).json({
        status: "login_success",
        message: "Google authentication successful.",
        token,
        user: safeUser,
      });

    } catch (error) {
      console.error("Google exchange error:", error);

      return res.status(500).json({
        status: "error",
        message: "Google authentication failed.",
      });
    }
  });

  // ======================================================
  // PASSWORD RESET OTP HASH HELPER
  // ======================================================

  const hashResetOTP = (otp) => {
    return crypto
      .createHmac("sha256", process.env.JWT_SECRET)
      .update(otp)
      .digest("hex");
  };

  // ======================================================
  // API 4: FORGOT PASSWORD
  // POST /forgot-password
  // ======================================================

  app.post("/forgot-password", async (req, res) => {
    try {
      const { email } = req.body;

      // 1. Validate email
      if (!email || typeof email !== "string") {
        return res.status(400).json({
          status: "error",
          message: "Please provide a valid email address.",
        });
      }

      const normalizedEmail = email.trim().toLowerCase();

      // Basic email format validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!emailRegex.test(normalizedEmail)) {
        return res.status(400).json({
          status: "error",
          message: "Please provide a valid email address.",
        });
      }

      // 2. Find account
      const user = await User.findOne({
        email: normalizedEmail,
      });

      // Same response for unknown emails and Google-only accounts.
      // This prevents revealing which email addresses have accounts.
      const genericResponse = {
        status: "success",
        message:
          "If an eligible account exists, password reset instructions will be sent to its registered email.",
      };

      if (
        !user ||
        !user.is_verified ||
        user.auth_provider === "google" ||
        !user.password
      ) {
        return res.status(200).json(genericResponse);
      }

      // 3. Prevent repeated OTP requests within 60 seconds
      const cooldown = 60 * 1000;

      if (
        user.reset_password_last_sent_at &&
        Date.now() - user.reset_password_last_sent_at.getTime() < cooldown
      ) {
        return res.status(200).json(genericResponse);
      }

      // 4. Generate secure six-digit OTP
      const otp = crypto
        .randomInt(100000, 1000000)
        .toString();

      // 5. Hash OTP
      const otpHash = hashResetOTP(otp);

      // 6. Store hash and expiry
      user.reset_password_otp_hash = otpHash;

      user.reset_password_otp_expiry = new Date(
        Date.now() + 10 * 60 * 1000
      );

      user.reset_password_attempts = 0;

      user.reset_password_last_sent_at = new Date();

      await user.save();

      // 7. Send OTP using your existing Brevo helper
      try {
        await sendEmail({
          to: normalizedEmail,
          subject: "DWJD Password Reset OTP",
          html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
              <h2>DWJD Password Reset</h2>

              <p>Hello ${user.first_name || "User"},</p>

              <p>
                We received a request to reset your DWJD account password.
              </p>

              <h1 style="letter-spacing: 8px;">${otp}</h1>

              <p>
                This OTP is valid for 10 minutes.
              </p>

              <p>
                Do not share this OTP with anyone.
              </p>

              <p>
                If you did not request this, you can ignore this email.
              </p>

              <br />

              <strong>DWJD Team</strong>
            </div>
          `,
        });
      } catch (emailError) {
        console.error(
          "Password reset email error:",
          emailError.response?.data || emailError.message
        );

        // Invalidate OTP if email delivery fails
        user.reset_password_otp_hash = null;
        user.reset_password_otp_expiry = null;
        user.reset_password_attempts = 0;
        user.reset_password_last_sent_at = null;

        await user.save();

        return res.status(500).json({
          status: "error",
          message: "Unable to send password reset email. Please try again later.",
        });
      }

      // 8. Success
      return res.status(200).json(genericResponse);

    } catch (error) {
      console.error("Forgot password error:", error);

      return res.status(500).json({
        status: "error",
        message: "Something went wrong. Please try again later.",
      });
    }
  });
  // ======================================================
  // API 5: RESET PASSWORD
  // POST /reset-password
  // ======================================================

  app.post("/reset-password", async (req, res) => {
    try {
      const { email, otp, newPassword } = req.body;

      // 1. Validate required fields
      if (
        !email ||
        typeof email !== "string" ||
        !otp ||
        typeof otp !== "string" ||
        !newPassword ||
        typeof newPassword !== "string"
      ) {
        return res.status(400).json({
          status: "error",
          message: "Email, OTP and new password are required.",
        });
      }

      const normalizedEmail = email.trim().toLowerCase();

      // 2. Validate OTP format
      if (!/^\d{6}$/.test(otp)) {
        return res.status(400).json({
          status: "error",
          message: "OTP must contain exactly six digits.",
        });
      }

      // 3. Validate new password
      if (newPassword.length < 8) {
        return res.status(400).json({
          status: "error",
          message: "Password must contain at least 8 characters.",
        });
      }

      if (newPassword.length > 128) {
        return res.status(400).json({
          status: "error",
          message: "Password cannot exceed 128 characters.",
        });
      }

      // 4. Find account
      const user = await User.findOne({
        email: normalizedEmail,
      });

      if (!user || !user.is_verified) {
        return res.status(400).json({
          status: "error",
          message: "Invalid or expired password reset request.",
        });
      }

      // 5. Only local-password accounts can reset this way
      if (user.auth_provider === "google" || !user.password) {
        return res.status(400).json({
          status: "error",
          message: "This account does not use password authentication.",
        });
      }

      // 6. Check whether reset OTP exists
      if (
        !user.reset_password_otp_hash ||
        !user.reset_password_otp_expiry
      ) {
        return res.status(400).json({
          status: "error",
          message: "No active password reset request. Request a new OTP.",
        });
      }

      // 7. Check OTP expiry
      if (user.reset_password_otp_expiry.getTime() <= Date.now()) {
        user.reset_password_otp_hash = null;
        user.reset_password_otp_expiry = null;
        user.reset_password_attempts = 0;
        user.reset_password_last_sent_at = null;

        await user.save();

        return res.status(400).json({
          status: "error",
          message: "OTP has expired. Please request a new OTP.",
        });
      }

      // 8. Check maximum attempts
      const MAX_ATTEMPTS = 5;

      if (user.reset_password_attempts >= MAX_ATTEMPTS) {
        user.reset_password_otp_hash = null;
        user.reset_password_otp_expiry = null;
        user.reset_password_attempts = 0;
        user.reset_password_last_sent_at = null;

        await user.save();

        return res.status(429).json({
          status: "error",
          message: "Maximum OTP attempts exceeded. Request a new OTP.",
        });
      }

      // 9. Compare submitted OTP with stored hash
      const submittedHash = hashResetOTP(otp);

      const storedHash = Buffer.from(
        user.reset_password_otp_hash,
        "hex"
      );

      const receivedHash = Buffer.from(
        submittedHash,
        "hex"
      );

      const otpMatches =
        storedHash.length === receivedHash.length &&
        crypto.timingSafeEqual(storedHash, receivedHash);

      if (!otpMatches) {
        user.reset_password_attempts += 1;

        const attemptsLeft =
          MAX_ATTEMPTS - user.reset_password_attempts;

        // Invalidate OTP after the fifth failed attempt
        if (attemptsLeft <= 0) {
          user.reset_password_otp_hash = null;
          user.reset_password_otp_expiry = null;
          user.reset_password_attempts = 0;
          user.reset_password_last_sent_at = null;
        }

        await user.save();

        return res.status(400).json({
          status: "error",
          message:
            attemptsLeft <= 0
              ? "Maximum OTP attempts exceeded. Request a new OTP."
              : `Incorrect OTP. ${attemptsLeft} attempts remaining.`,
        });
      }

      // 10. Hash the new password
      const saltRounds = 12;

      const hashedPassword = await bcrypt.hash(
        newPassword,
        saltRounds
      );

      // 11. Update password and clear reset information
      user.password = hashedPassword;

      user.reset_password_otp_hash = null;
      user.reset_password_otp_expiry = null;
      user.reset_password_attempts = 0;
      user.reset_password_last_sent_at = null;

      await user.save();

      // 12. Success
      return res.status(200).json({
        status: "success",
        message: "Password reset successfully. Please login with your new password.",
      });

    } catch (error) {
      console.error("Reset password error:", error);

      return res.status(500).json({
        status: "error",
        message: "Unable to reset password. Please try again later.",
      });
    }
  });
 
/* =========================================================
   OCCASION MONEY DONATION APIs
   Base URL: /api/occasion-donations

   API 1: POST   /api/occasion-donations
   API 2: POST   /api/occasion-donations/:id/create-order
   API 3: POST   /api/occasion-donations/:id/verify-payment
   API 4: POST   /api/occasion-donations/:id/upload-media
   API 5: GET    /api/occasion-donations/my-requests
========================================================= */


/* =========================================================
   API 1: CREATE OCCASION DONATION
   POST /api/occasion-donations

   Content-Type: application/json

   Creates MongoDB record only.
   Does NOT upload files to Google Drive.
========================================================= */

app.post(
  "/api/occasion-donations",
  requireOccasionDonationUser,
  async (req, res) => {
    try {
      const user = req.occasionDonationUser;

      const {
        occasionType,
        occasionTitle,
        occasionDate,
        scheduledWishTime,
        recipientName,
        recipientEmail,
        recipientPhone,
        recipientContactConsent,
        dedicationName,
        donorMessage,
        amount,
        termsAccepted,
      } = req.body || {};

      // 1. Validate occasion.
      const allowedOccasions = [
        "Birthday",
        "Wedding",
        "Wedding Anniversary",
        "Engagement",
        "Graduation",
        "New Job",
        "Promotion",
        "Baby Shower",
        "Newborn / Naming Ceremony",
        "Housewarming",
        "Retirement",
        "Festival",
        "Memorial / In Loving Memory",
        "Get Well Soon",
        "Thank You",
        "Just Because",
        "Other",
      ];

      if (!allowedOccasions.includes(occasionType)) {
        return res.status(400).json({
          status: "error",
          message: "Please select a valid occasion.",
        });
      }

      // 2. Validate recipient name.
      if (
        typeof recipientName !== "string" ||
        !recipientName.trim()
      ) {
        return res.status(400).json({
          status: "error",
          message: "Recipient name is required.",
        });
      }

      const normalizedRecipientEmail = String(
        recipientEmail || ""
      )
        .trim()
        .toLowerCase();

      const normalizedRecipientPhone = String(
        recipientPhone || ""
      ).trim();

      // 3. Recipient must have email or phone.
      if (
        !normalizedRecipientEmail &&
        !normalizedRecipientPhone
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Recipient email or phone number is required.",
        });
      }

      // 4. Validate email.
      if (
        normalizedRecipientEmail &&
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          normalizedRecipientEmail
        )
      ) {
        return res.status(400).json({
          status: "error",
          message: "Please provide a valid recipient email.",
        });
      }

      // 5. Validate amount.
      const donationAmount = Number(amount);

      if (
        !Number.isSafeInteger(donationAmount) ||
        donationAmount < 1 ||
        donationAmount > 1000000
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Donation amount must be between ₹1 and ₹10,00,000.",
        });
      }

      // 6. Validate consent.
      const hasContactConsent =
        recipientContactConsent === true ||
        recipientContactConsent === "true";

      const hasAcceptedTerms =
        termsAccepted === true ||
        termsAccepted === "true";

      if (!hasContactConsent || !hasAcceptedTerms) {
        return res.status(400).json({
          status: "error",
          message:
            "Recipient contact consent and donation terms acceptance are required.",
        });
      }

      // 7. Validate scheduled occasion date.
      const scheduledAt = getOccasionScheduledAt(
        occasionDate,
        scheduledWishTime
      );

  const minimumAllowedTime = new Date(Date.now() + 5 * 60 * 1000);

if (!scheduledAt || scheduledAt < minimumAllowedTime) {
  return res.status(400).json({
    status: "error",
    message: "Please schedule the greeting at least 5 minutes in advance.",
  });
}
      // 8. Donor snapshot.
      const donorName =
        `${user.first_name || ""} ${user.last_name || ""}`.trim() ||
        user.username ||
        "";

      // 9. Save donation in MongoDB.
      // Media stays empty until payment is verified.
      const donation = await OccasionDonation.create({
        donor: user._id,

        donorSnapshot: {
          name: donorName,
          email: user.email || "",
          phone: user.phone || "",
        },

        occasionType,

        occasionTitle: String(
          occasionTitle || ""
        ).trim(),

        occasionDate: new Date(
          `${occasionDate}T00:00:00+05:30`
        ),

        scheduledWishTime,
        timeZone: "Asia/Kolkata",
        scheduledAt,

        recipientName: recipientName.trim(),
        recipientEmail: normalizedRecipientEmail,
        recipientPhone: normalizedRecipientPhone,

        recipientContactConsent: true,

        dedicationName: String(
          dedicationName || ""
        ).trim(),

        donorMessage: String(
          donorMessage || ""
        ).trim(),

        amount: donationAmount,
        currency: "INR",

        media: [],

        termsAccepted: true,

        paymentStatus: "created",
        adminStatus: "awaiting_payment",
        greetingStatus: "not_scheduled",
      });

      return res.status(201).json({
        status: "success",
        message:
          "Occasion donation request created. Continue to payment.",

        donation: {
          id: String(donation._id),
          referenceCode: donation.referenceCode,
          amount: donation.amount,
          currency: donation.currency,
          paymentStatus: donation.paymentStatus,
          adminStatus: donation.adminStatus,
          media: donation.media,
        },
      });

    } catch (error) {
      console.error(
        "Create occasion donation error:",
        error
      );

      if (error.name === "ValidationError") {
        return res.status(400).json({
          status: "validation_error",
          message: error.message,
        });
      }

      return res.status(500).json({
        status: "error",
        message: "Unable to create occasion donation.",
      });
    }
  }
);


/* =========================================================
   API 2: CREATE RAZORPAY ORDER
   POST /api/occasion-donations/:id/create-order

   Amount is always taken from MongoDB.
========================================================= */

app.post(
  "/api/occasion-donations/:id/create-order",
  requireOccasionDonationUser,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation ID.",
        });
      }

      if (
        !process.env.RAZORPAY_KEY_ID ||
        !process.env.RAZORPAY_KEY_SECRET
      ) {
        return res.status(503).json({
          status: "error",
          message: "Razorpay is not configured.",
        });
      }

      const donation = await OccasionDonation.findOne({
        _id: id,
        donor: req.occasionDonationUser._id,
      });

      if (!donation) {
        return res.status(404).json({
          status: "error",
          message: "Donation request not found.",
        });
      }

      if (donation.paymentStatus === "paid") {
        return res.status(409).json({
          status: "error",
          message: "This donation has already been paid.",
        });
      }

      if (
        ["approved", "rejected"].includes(
          donation.adminStatus
        )
      ) {
        return res.status(409).json({
          status: "error",
          message:
            "This donation request can no longer be paid.",
        });
      }

      // Reuse existing active Razorpay order.
      if (donation.razorpayOrderId) {
        const existingOrder = await razorpay.orders
          .fetch(donation.razorpayOrderId)
          .catch(() => null);

        if (
          existingOrder &&
          existingOrder.status === "created"
        ) {
          return res.status(200).json({
            status: "success",
            message: "Existing Razorpay order reused.",

            order: {
              id: existingOrder.id,
              amount: existingOrder.amount,
              currency: existingOrder.currency,
            },

            prefill: {
              name: donation.donorSnapshot.name,
              email: donation.donorSnapshot.email,
              contact: donation.donorSnapshot.phone,
            },
          });
        }
      }

      // Amount comes from database, not frontend.
      const amountInPaise = donation.amount * 100;

      if (
        !Number.isSafeInteger(amountInPaise) ||
        amountInPaise < 100
      ) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation amount.",
        });
      }

      const order = await razorpay.orders.create({
        amount: amountInPaise,
        currency: "INR",
        receipt: donation.referenceCode,

        notes: {
          donation_id: String(donation._id),
          reference_code: donation.referenceCode,
          donation_type: "occasion_money_donation",
        },
      });

      donation.razorpayOrderId = order.id;
      donation.paymentStatus = "pending";

      await donation.save();

      return res.status(201).json({
        status: "success",
        message: "Razorpay order created successfully.",

        order: {
          id: order.id,
          amount: order.amount,
          currency: order.currency,
        },

        prefill: {
          name: donation.donorSnapshot.name,
          email: donation.donorSnapshot.email,
          contact: donation.donorSnapshot.phone,
        },
      });

    } catch (error) {
      console.error(
        "Occasion donation Razorpay order error:",
        error
      );

      return res.status(500).json({
        status: "error",
        message: "Unable to create Razorpay order.",
      });
    }
  }
);


/* =========================================================
   API 3: VERIFY RAZORPAY PAYMENT
   POST /api/occasion-donations/:id/verify-payment

   Payment is marked paid only after:
   1. Signature validation.
   2. Razorpay payment fetch.
   3. Order ID validation.
   4. Amount validation.
   5. Captured payment status validation.
========================================================= */

app.post(
  "/api/occasion-donations/:id/verify-payment",
  requireOccasionDonationUser,
  async (req, res) => {
    try {
      const { id } = req.params;

      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
      } = req.body || {};

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation ID.",
        });
      }

      const donation = await OccasionDonation.findOne({
        _id: id,
        donor: req.occasionDonationUser._id,
      });

      if (!donation) {
        return res.status(404).json({
          status: "error",
          message: "Donation request not found.",
        });
      }

      // Idempotency.
      if (
        donation.paymentStatus === "paid" &&
        donation.razorpayPaymentId === razorpay_payment_id
      ) {
        return res.status(200).json({
          status: "success",
          message: "Payment was already verified.",

          donation: {
            id: String(donation._id),
            referenceCode: donation.referenceCode,
            paymentStatus: donation.paymentStatus,
            adminStatus: donation.adminStatus,
            amount: donation.amount,
            currency: donation.currency,
          },
        });
      }

      if (
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Payment verification details are missing.",
        });
      }

      if (
        razorpay_order_id !== donation.razorpayOrderId
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Razorpay order does not match this donation.",
        });
      }

      if (!process.env.RAZORPAY_KEY_SECRET) {
        return res.status(503).json({
          status: "error",
          message: "Razorpay is not configured.",
        });
      }

      // Verify Razorpay checkout signature.
      const expectedSignature = crypto
        .createHmac(
          "sha256",
          process.env.RAZORPAY_KEY_SECRET
        )
        .update(
          `${razorpay_order_id}|${razorpay_payment_id}`
        )
        .digest("hex");

      const receivedBuffer = Buffer.from(
        String(razorpay_signature),
        "utf8"
      );

      const expectedBuffer = Buffer.from(
        expectedSignature,
        "utf8"
      );

      if (
        receivedBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(
          receivedBuffer,
          expectedBuffer
        )
      ) {
        return res.status(400).json({
          status: "error",
          message: "Invalid Razorpay payment signature.",
        });
      }

      // Fetch payment directly from Razorpay.
      const payment = await razorpay.payments.fetch(
        razorpay_payment_id
      );

      if (
        payment.order_id !== donation.razorpayOrderId ||
        Number(payment.amount) !== donation.amount * 100 ||
        payment.currency !== "INR" ||
        payment.status !== "captured"
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Payment is not captured or payment amount does not match.",
        });
      }

      // Save verified payment in MongoDB.
      donation.paymentStatus = "paid";
      donation.adminStatus = "pending_review";

      donation.razorpayPaymentId = payment.id;
      donation.razorpaySignature = razorpay_signature;

      donation.paidAt = payment.created_at
        ? new Date(payment.created_at * 1000)
        : new Date();

      await donation.save();

      return res.status(200).json({
        status: "success",
        message:
          "Payment verified successfully. Your request is awaiting review.",

        donation: {
          id: String(donation._id),
          referenceCode: donation.referenceCode,
          paymentStatus: donation.paymentStatus,
          adminStatus: donation.adminStatus,
          amount: donation.amount,
          currency: donation.currency,
        },
      });

    } catch (error) {
      console.error(
        "Occasion donation payment verification error:",
        error
      );

      return res.status(500).json({
        status: "error",
        message: "Unable to verify donation payment.",
      });
    }
  }
);


/* =========================================================
   API 4: UPLOAD MEDIA AFTER SUCCESSFUL PAYMENT
   POST /api/occasion-donations/:id/upload-media

   Content-Type: multipart/form-data
   Field name: media

   Google Drive upload is allowed only when:
   paymentStatus === "paid"

   Maximum:
   - 5 files
   - 50 MB per file
   - 100 MB total
========================================================= */

app.post(
  "/api/occasion-donations/:id/upload-media",

  requireOccasionDonationUser,

  (req, res, next) => {
    occasionDonationUpload.array("media", 5)(
      req,
      res,
      (error) => {
        if (!error) {
          return next();
        }

        const tooLarge =
          error instanceof multer.MulterError &&
          error.code === "LIMIT_FILE_SIZE";

        return res.status(tooLarge ? 413 : 400).json({
          status: "error",
          message: tooLarge
            ? "Each media file must be below 50 MB."
            : error.message || "Media upload failed.",
        });
      }
    );
  },

  async (req, res) => {
    const uploadedMedia = [];

    try {
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation ID.",
        });
      }

      const donation = await OccasionDonation.findOne({
        _id: id,
        donor: req.occasionDonationUser._id,
      });

      if (!donation) {
        return res.status(404).json({
          status: "error",
          message: "Donation request not found.",
        });
      }

      // Critical security check:
      // No Drive upload before verified payment.
      if (
        donation.paymentStatus !== "paid" ||
        !donation.razorpayPaymentId
      ) {
        return res.status(403).json({
          status: "payment_required",
          message:
            "Please complete and verify payment before uploading media.",
        });
      }

      // Prevent uploading the same donation media repeatedly.
      if (donation.media && donation.media.length > 0) {
        return res.status(409).json({
          status: "error",
          message:
            "Media has already been uploaded for this donation.",
          media: donation.media,
        });
      }

      const files = req.files || [];

      if (files.length === 0) {
        return res.status(400).json({
          status: "error",
          message: "Please select at least one media file.",
        });
      }

      // Validate total upload size.
      const totalSize = files.reduce(
        (total, file) => total + file.size,
        0
      );

      if (totalSize > 100 * 1024 * 1024) {
        return res.status(413).json({
          status: "error",
          message:
            "Total media upload size must not exceed 100 MB.",
        });
      }

      // Upload files to Google Drive.
      for (const file of files) {
        const media = await uploadOccasionDonationFile(
          file,
          donation.recipientName
        );

        uploadedMedia.push(media);
      }

      // Save uploaded media information in MongoDB.
      donation.media = uploadedMedia;

      await donation.save();

      return res.status(200).json({
        status: "success",
        message:
          "Media uploaded successfully and saved to your donation.",

        donation: {
          id: String(donation._id),
          referenceCode: donation.referenceCode,
          paymentStatus: donation.paymentStatus,
          media: donation.media,
        },
      });

    } catch (error) {
      console.error(
        "Occasion donation media upload error:",
        error
      );

      // Remove Drive files if MongoDB save or upload fails.
      for (const media of uploadedMedia) {
        try {
          await drive.files.delete({
            fileId: media.driveFileId,
          });
        } catch (cleanupError) {
          console.error(
            "Occasion donation Drive cleanup error:",
            cleanupError.message
          );
        }
      }

      if (error.name === "ValidationError") {
        return res.status(400).json({
          status: "validation_error",
          message: error.message,
        });
      }

      return res.status(500).json({
        status: "error",
        message:
          "Media upload failed. Your verified payment remains recorded. Please retry the media upload.",
      });
    }
  }
);


/* =========================================================
   API 5: GET MY OCCASION DONATIONS
   GET /api/occasion-donations/my-requests

   Returns the logged-in user's donation history.
========================================================= */

app.get(
  "/api/occasion-donations/my-requests",

  requireOccasionDonationUser,

  async (req, res) => {
    try {
      const donations = await OccasionDonation.find({
        donor: req.occasionDonationUser._id,
      })
        .select("-razorpaySignature")
        .sort({ createdAt: -1 })
        .lean();

      return res.status(200).json({
        status: "success",
        message:
          "Occasion donation history retrieved successfully.",

        count: donations.length,
        donations,
      });

    } catch (error) {
      console.error(
        "Fetch occasion donation history error:",
        error
      );

      return res.status(500).json({
        status: "error",
        message: "Unable to retrieve donation history.",
      });
    }
  }
);


/* =========================================================
   OCCASION DONATION ADMIN APIs
   Uses existing:
   - OccasionDonation
   - requireAdmin
   - razorpay
   - mongoose
   ========================================================= */

// 1. GET ALL OCCASION DONATIONS
// GET /api/occasion-donations/admin?status=pending_review

app.get(
  "/api/occasion-donations/admin",
  requireAdmin,
  async (req, res) => {
    try {
      const { status = "pending_review" } = req.query;

      const allowedStatuses = [
        "pending_review",
        "approved",
        "rejected",
        "all",
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation status.",
        });
      }

      const filter = {
        paymentStatus: { $in: ["paid", "refunded"] },
      };

      if (status !== "all") {
        filter.adminStatus = status;
      }

      const donations = await OccasionDonation.find(filter)
        .select("-razorpaySignature")
        .sort({ createdAt: -1 })
        .lean();

      return res.status(200).json({
        status: "success",
        message: "Occasion donations retrieved successfully.",
        count: donations.length,
        donations,
      });
    } catch (error) {
      console.error("Admin occasion donation fetch error:", error);

      return res.status(500).json({
        status: "error",
        message: "Unable to retrieve occasion donations.",
      });
    }
  }
);



/* =========================================================
   APPROVE OCCASION DONATION + GENERATE UNIQUE WISHES LINK

   PATCH /api/occasion-donations/admin/:id/approve

   Workflow:
   1. Admin approves donation.
   2. Generate secure unique token.
   3. Store SHA-256 hash only.
   4. Schedule email for 2 minutes before scheduledAt.
   5. Wishes page remains locked until scheduledAt.
========================================================= */

app.patch(
  "/api/occasion-donations/admin/:id/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation ID.",
        });
      }

      const now = new Date();

      // Fetch the pending paid donation.
      const existingDonation = await OccasionDonation.findOne({
        _id: id,
        paymentStatus: "paid",
        adminStatus: "pending_review",
      });

      if (!existingDonation) {
        return res.status(409).json({
          status: "error",
          message:
            "Donation not found, already reviewed, or payment is not completed.",
        });
      }

      if (!existingDonation.recipientEmail) {
        return res.status(400).json({
          status: "error",
          message:
            "Recipient email is required to send the scheduled wishes invitation.",
        });
      }

      if (
        !existingDonation.scheduledAt ||
        existingDonation.scheduledAt <= now
      ) {
        return res.status(409).json({
          status: "error",
          message:
            "The scheduled occasion time has already passed.",
        });
      }

      // Generate a cryptographically secure token.
      const rawToken = crypto.randomBytes(32).toString("hex");

      // Store only the SHA-256 hash in MongoDB.
      const tokenHash = crypto
        .createHash("sha256")
        .update(rawToken)
        .digest("hex");

      // Email is scheduled 2 minutes before the occasion.
      // If approval happens inside that 2-minute window,
      // the email is due immediately.
      const twoMinutesBefore = new Date(
        existingDonation.scheduledAt.getTime() - 2 * 60 * 1000
      );

      const emailScheduledAt =
        twoMinutesBefore > now ? twoMinutesBefore : now;

      const donation = await OccasionDonation.findOneAndUpdate(
        {
          _id: id,
          paymentStatus: "paid",
          adminStatus: "pending_review",
          scheduledAt: { $gt: now },
        },
        {
          $set: {
            adminStatus: "approved",

            greetingStatus: "scheduled",

            reviewedBy: req.admin.id,
            reviewedAt: now,

            rejectionReason: "",
            greetingLastError: "",

            wishAccessTokenHash: tokenHash,

            wishEmailStatus: "pending",
            wishEmailScheduledAt: emailScheduledAt,
            wishEmailSentAt: null,
            wishEmailAttempts: 0,
            wishEmailLastError: "",

            wishPageStatus: "locked",
            wishPagePublishedAt: null,
          },
        },
        {
          new: true,
          runValidators: true,
        }
      ).select("-razorpaySignature");

      if (!donation) {
        return res.status(409).json({
          status: "error",
          message:
            "This donation was already reviewed or its scheduled time has passed.",
        });
      }

      // The original token is used only to construct the email link.
      // It is never stored in MongoDB or returned in this response.
      const frontendUrl = (
        process.env.FRONTEND_URL || "https://www.dwjd.online"
      ).replace(/\/+$/, "");

      const wishesUrl =
        `${frontendUrl}/wishes/${rawToken}`;

      return res.status(200).json({
        status: "success",
        message:
          "Occasion donation approved. The recipient invitation email has been scheduled.",

        donation: {
          id: String(donation._id),
          referenceCode: donation.referenceCode,
          adminStatus: donation.adminStatus,
          paymentStatus: donation.paymentStatus,
          greetingStatus: donation.greetingStatus,
          wishEmailStatus: donation.wishEmailStatus,
          wishEmailScheduledAt: donation.wishEmailScheduledAt,
          wishPageStatus: donation.wishPageStatus,
        },
      });

    } catch (error) {
      console.error(
        "Approve occasion donation error:",
        error
      );

      return res.status(500).json({
        status: "error",
        message: "Unable to approve occasion donation.",
      });
    }
  }
);



// 3. REJECT OCCASION DONATION + INITIATE RAZORPAY REFUND
// PATCH /api/occasion-donations/admin/:id/reject
//
// Request body:
// {
//   "reason": "Invalid donation details"
// }

app.patch(
  "/api/occasion-donations/admin/:id/reject",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { reason } = req.body || {};

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation ID.",
        });
      }

      if (
        typeof reason !== "string" ||
        !reason.trim()
      ) {
        return res.status(400).json({
          status: "error",
          message: "Rejection reason is required.",
        });
      }

      if (
        !process.env.RAZORPAY_KEY_ID ||
        !process.env.RAZORPAY_KEY_SECRET
      ) {
        return res.status(503).json({
          status: "error",
          message: "Razorpay is not configured.",
        });
      }

      const donation = await OccasionDonation.findOne({
        _id: id,
        paymentStatus: "paid",
        adminStatus: "pending_review",
      });

      if (!donation) {
        return res.status(404).json({
          status: "error",
          message:
            "Paid donation not found or it has already been reviewed.",
        });
      }

      if (!donation.razorpayPaymentId) {
        return res.status(400).json({
          status: "error",
          message: "Razorpay payment ID is missing.",
        });
      }

      // Prevent duplicate refund requests.
      if (donation.refundId) {
        return res.status(409).json({
          status: "error",
          message:
            "A refund has already been initiated for this donation.",
          refundId: donation.refundId,
        });
      }

      // Razorpay amount is in paise.
      const refundAmount = Math.round(
        Number(donation.amount) * 100
      );

      if (!Number.isSafeInteger(refundAmount) || refundAmount <= 0) {
        return res.status(400).json({
          status: "error",
          message: "Invalid donation refund amount.",
        });
      }

      // Initiate Razorpay refund.
      const refund = await razorpay.payments.refund(
        donation.razorpayPaymentId,
        {
          amount: refundAmount,
          notes: {
            donationId: String(donation._id),
            referenceCode: donation.referenceCode || "",
            rejectionReason: reason.trim(),
            rejectedBy: String(req.admin.id),
          },
        }
      );

      // Store refund details.
      donation.refundId = refund.id || "";
      donation.rejectionReason = reason.trim();
      donation.reviewedBy = req.admin.id;
      donation.reviewedAt = new Date();
      donation.greetingStatus = "cancelled";

      if (refund.status === "processed") {
        donation.paymentStatus = "refunded";
        donation.refundedAt = new Date();
        donation.adminStatus = "rejected";
        donation.refundError = "";
      } else {
        // Payment remains paid until Razorpay confirms the refund.
        donation.adminStatus = "rejected";
        donation.refundError =
          `Refund initiated with status: ${refund.status}`;
      }

      await donation.save();

      return res.status(200).json({
        status: "success",
        message:
          refund.status === "processed"
            ? "Donation rejected and refund completed."
            : "Donation rejected and refund initiated. Awaiting Razorpay confirmation.",
        refund: {
          id: refund.id,
          status: refund.status,
          amount: refund.amount,
          currency: refund.currency,
        },
        donation: {
          id: donation._id,
          referenceCode: donation.referenceCode,
          adminStatus: donation.adminStatus,
          paymentStatus: donation.paymentStatus,
          refundId: donation.refundId,
          refundedAt: donation.refundedAt,
        },
      });
    } catch (error) {
      console.error("Reject occasion donation error:", error);

      return res.status(500).json({
        status: "error",
        message:
          "Unable to complete the rejection or refund request.",
        error: error.error?.description || error.message,
      });
    }
  }
);


/* =========================================================
   OCCASION WISHES EMAIL SCHEDULER

   Sends invitation email 2 minutes before scheduledAt.

   Retry policy:
   - Maximum 5 attempts.
   - Claims each email atomically.
   - Recovers stale sending records after 10 minutes.
========================================================= */

async function processOccasionWishEmails() {
  const now = new Date();

  try {
    // Recover records left in "sending" if the server
    // crashed or restarted while processing an email.
    await OccasionDonation.updateMany(
      {
        wishEmailStatus: "sending",
        updatedAt: {
          $lte: new Date(now.getTime() - 10 * 60 * 1000),
        },
        wishEmailAttempts: { $lt: 5 },
      },
      {
        $set: {
          wishEmailStatus: "failed",
          wishEmailLastError:
            "Previous email attempt did not finish. Retrying.",
        },
      }
    );

    const dueDonations = await OccasionDonation.find({
      adminStatus: "approved",
      paymentStatus: "paid",
      wishEmailStatus: { $in: ["pending", "failed"] },
      wishEmailScheduledAt: { $lte: now },
      wishEmailAttempts: { $lt: 5 },
      recipientEmail: { $ne: "" },
    })
      .select("_id")
      .limit(20)
      .lean();

    for (const item of dueDonations) {
      try {
        // Atomically claim the email to prevent two workers
        // from processing the same donation simultaneously.
        const donation = await OccasionDonation.findOneAndUpdate(
          {
            _id: item._id,
            adminStatus: "approved",
            paymentStatus: "paid",
            wishEmailStatus: { $in: ["pending", "failed"] },
            wishEmailAttempts: { $lt: 5 },
            wishEmailScheduledAt: { $lte: new Date() },
          },
          {
            $set: {
              wishEmailStatus: "sending",
              wishEmailLastError: "",
            },
            $inc: {
              wishEmailAttempts: 1,
            },
          },
          {
            new: true,
          }
        ).select("+wishAccessTokenEncrypted");

        if (!donation) {
          continue;
        }

        if (!donation.wishAccessTokenEncrypted) {
          throw new Error("Encrypted wishes token is missing.");
        }

        const rawToken = decryptWishToken(
          donation.wishAccessTokenEncrypted
        );

        const frontendUrl = (
          process.env.FRONTEND_URL || "https://www.dwjd.online"
        ).replace(/\/+$/, "");

        const wishesUrl =
          `${frontendUrl}/wishes/${rawToken}`;

        const recipientName = escapeWishHtml(
          donation.recipientName
        );

        const occasionType = escapeWishHtml(
          donation.occasionType
        );

        const occasionTitle = escapeWishHtml(
          donation.occasionTitle || occasionType
        );

        const scheduledTime = new Intl.DateTimeFormat(
          "en-IN",
          {
            dateStyle: "full",
            timeStyle: "short",
            timeZone: "Asia/Kolkata",
          }
        ).format(donation.scheduledAt);

        const safeScheduledTime =
          escapeWishHtml(scheduledTime);

        const html = `
          <!DOCTYPE html>
          <html>
          <body style="
            margin:0;
            padding:30px 15px;
            background:#f8f5ff;
            font-family:Arial,sans-serif;
          ">
            <div style="
              max-width:560px;
              margin:auto;
              padding:35px 25px;
              background:#ffffff;
              border-radius:18px;
              text-align:center;
            ">
              <div style="font-size:45px;">🎁</div>

              <h1 style="color:#7c3aed;">
                A Special Surprise Is Waiting!
              </h1>

              <p style="font-size:17px;color:#334155;">
                Hello ${recipientName},
              </p>

              <p style="
                color:#475569;
                line-height:1.8;
              ">
                Someone has prepared a special surprise
                for you for your ${occasionType}.
              </p>

              <h2 style="color:#9333ea;">
                ${occasionTitle}
              </h2>

              <p style="color:#64748b;">
                Your wishes will unlock at:
              </p>

              <p style="
                font-weight:bold;
                color:#334155;
              ">
                ${safeScheduledTime} IST
              </p>

              <a
                href="${wishesUrl}"
                style="
                  display:inline-block;
                  margin-top:20px;
                  padding:15px 28px;
                  background:#7c3aed;
                  color:#ffffff;
                  text-decoration:none;
                  border-radius:10px;
                  font-weight:bold;
                "
              >
                Open Your Surprise
              </a>

              <p style="
                margin-top:25px;
                font-size:12px;
                color:#94a3b8;
              ">
                Your surprise will become visible
                at the scheduled time.
              </p>

              <p style="
                margin-top:25px;
                color:#64748b;
              ">
                With love,<br/>
                <strong>DWJD Team</strong>
              </p>
            </div>
          </body>
          </html>
        `;

        await sendEmail({
          to: donation.recipientEmail,
          subject: "🎁 A Special Surprise Is Waiting for You!",
          html,
        });

        await OccasionDonation.updateOne(
          {
            _id: donation._id,
            wishEmailStatus: "sending",
          },
          {
            $set: {
              wishEmailStatus: "sent",
              wishEmailSentAt: new Date(),
              wishEmailLastError: "",
            },
          }
        );

        console.log(
          "Occasion wishes invitation email sent:",
          donation.referenceCode
        );

      } catch (emailError) {
        console.error(
          "Occasion wishes email error:",
          emailError.response?.data || emailError.message
        );

        await OccasionDonation.updateOne(
          {
            _id: item._id,
            wishEmailStatus: "sending",
          },
          {
            $set: {
              wishEmailStatus: "failed",
              wishEmailLastError: String(
                emailError.message || "Email delivery failed."
              ).slice(0, 2000),
            },
          }
        );
      }
    }
  } catch (error) {
    console.error(
      "Occasion wishes scheduler error:",
      error
    );
  }
}

// Check for due emails every minute.
cron.schedule("* * * * *", () => {
  processOccasionWishEmails();
});

/* =========================================================
   PUBLIC OCCASION WISHES API

   GET /api/occasion-donations/public/wishes/:token

   No authentication required.
========================================================= */

app.get(
  "/api/occasion-donations/public/wishes/:token",
  async (req, res) => {
    try {
      const { token } = req.params;

      if (
        typeof token !== "string" ||
        !/^[a-f0-9]{64}$/i.test(token)
      ) {
        return res.status(404).json({
          ok: false,
          status: "error",
          message: "This wishes link is invalid.",
        });
      }

      const tokenHash = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

      const donation = await OccasionDonation.findOne({
        wishAccessTokenHash: tokenHash,
      }).lean();

      if (!donation) {
        return res.status(404).json({
          ok: false,
          status: "error",
          message: "This wishes link is invalid or unavailable.",
        });
      }

      if (
        donation.wishPageStatus === "disabled" ||
        donation.wishPageStatus === "expired"
      ) {
        return res.status(410).json({
          ok: false,
          status: donation.wishPageStatus,
          message: "This wishes page is no longer available.",
        });
      }

      if (
        donation.adminStatus !== "approved" ||
        donation.paymentStatus !== "paid"
      ) {
        return res.status(404).json({
          ok: false,
          status: "error",
          message: "This wishes page is unavailable.",
        });
      }

      const now = new Date();

      if (
        donation.wishPageExpiresAt &&
        now >= new Date(donation.wishPageExpiresAt)
      ) {
        return res.status(410).json({
          ok: false,
          status: "expired",
          message: "This wishes page has expired.",
        });
      }

      // LOCKED PAGE
      if (now < new Date(donation.scheduledAt)) {
        return res.status(200).json({
          ok: true,
          status: "locked",
          wish: {
            recipientName: donation.recipientName,
            occasionType: donation.occasionType,
            occasionTitle: donation.occasionTitle,
            scheduledAt: donation.scheduledAt,
          },
        });
      }

      // PUBLISHED PAGE
      await OccasionDonation.updateOne(
        {
          _id: donation._id,
          wishPageStatus: "locked",
        },
        {
          $set: {
            wishPageStatus: "published",
            wishPagePublishedAt: now,
          },
        }
      );

      return res.status(200).json({
        ok: true,
        status: "published",
        wish: {
          recipientName: donation.recipientName,
          occasionType: donation.occasionType,
          occasionTitle: donation.occasionTitle,
          dedicationName: donation.dedicationName,
          donorMessage: donation.donorMessage,
          scheduledAt: donation.scheduledAt,
          media: (donation.media || []).map((item) => ({
            url: item.url,
            name: item.name,
            mimeType: item.mimeType,
            resourceType: item.resourceType,
          })),
        },
      });

    } catch (error) {
      console.error(
        "Public occasion wishes API error:",
        error
      );

      return res.status(500).json({
        ok: false,
        status: "error",
        message: "Unable to load this wishes page.",
      });
    }
  }
);


/* =========================================================
   END OF OCCASION MONEY DONATION APIs
========================================================= */

  /* ================= SERVER START ================= */
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));