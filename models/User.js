
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    // ========================================
    // BASIC USER INFORMATION
    // ========================================

    username: {
      type: String,
      required: true,
      trim: true,
      minlength: 6,
    },

    first_name: {
      type: String,
      required: true,
      trim: true,
    },

    last_name: {
      type: String,
      required: true,
      trim: true,
    },

    phone: {
      type: String,
      default: undefined,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    // ========================================
    // USER ROLE
    // ========================================

    user_type: {
      type: String,
      enum: ["user", "rider"],
      default: "user",
      required: true,
    },

    // ========================================
    // ACCOUNT STATUS
    // ========================================

    is_active: {
      type: Boolean,
      default: true,
    },

    // Increment this to invalidate existing JWT sessions.
    token_version: {
      type: Number,
      default: 0,
      min: 0,
    },

    // ========================================
    // AUTHENTICATION PROVIDER
    // ========================================

    auth_provider: {
      type: String,
      enum: ["local", "google"],
      default: "local",
      required: true,
    },

    google_id: {
      type: String,
      default: undefined,
    },

    password: {
      type: String,
      default: null,
      required: function () {
        return this.auth_provider === "local";
      },
    },

    // ========================================
    // PROFILE INFORMATION
    // ========================================

    profile_image: {
      type: String,
      default: "",
    },

    // ========================================
    // EMAIL VERIFICATION
    // ========================================

    is_verified: {
      type: Boolean,
      default: false,
    },

    otp: {
      type: String,
      default: null,
    },

    otp_expiry: {
      type: Date,
      default: null,
    },

    // ========================================
    // FORGOT PASSWORD / RESET PASSWORD
    // ========================================

    reset_password_otp_hash: {
      type: String,
      default: null,
    },

    reset_password_otp_expiry: {
      type: Date,
      default: null,
    },

    reset_password_attempts: {
      type: Number,
      default: 0,
      min: 0,
    },

    reset_password_last_sent_at: {
      type: Date,
      default: null,
    },

    // ========================================
    // RIDER APPROVAL
    // ========================================

    is_rider_approved: {
      type: Boolean,
      default: false,
    },

    rider_approved_at: {
      type: Date,
      default: null,
    },

  },
  {
    timestamps: true,
  }
);

// ========================================
// DATABASE INDEXES
// ========================================

// Unique username
userSchema.index(
  { username: 1 },
  { unique: true }
);

// Unique email
userSchema.index(
  { email: 1 },
  { unique: true }
);

// Unique phone, allowing missing values
userSchema.index(
  { phone: 1 },
  {
    unique: true,
    sparse: true,
  }
);

// Unique Google ID when present
userSchema.index(
  { google_id: 1 },
  {
    unique: true,
    partialFilterExpression: {
      google_id: { $type: "string" },
    },
  }
);

// Query accounts by role and status
userSchema.index({
  user_type: 1,
  is_active: 1,
});

// ========================================
// EXPORT MODEL
// ========================================

module.exports =
  mongoose.models.User ||
  mongoose.model("User", userSchema);
