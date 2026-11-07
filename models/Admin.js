
const mongoose = require("mongoose");

// ============================================
// ALLOWED ACCOUNT ROLES
// ============================================

const ALLOWED_ADMIN_ROLES = [
  "gm",
  "admin",
];

// ============================================
// ALLOWED RESPONSIBILITIES
// ============================================

const ALLOWED_RESPONSIBILITIES = [
  "create_promotion",
  "create_rider",
];

// ============================================
// ADMIN SCHEMA
// ============================================

const adminSchema = new mongoose.Schema(
  {
    // ========================================
    // PERSONAL INFORMATION
    // ========================================

    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
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
      required: true,
      unique: true,
      trim: true,
    },

    profile_image: {
      type: String,
      default: "",
      trim: true,
    },

    // ========================================
    // ACCOUNT SECURITY
    // ========================================

    password: {
      type: String,
      required: true,
      select: false,
    },

    must_change_password: {
      type: Boolean,
      default: true,
    },

    // ========================================
    // ACCOUNT TYPE
    // ========================================

    user_type: {
      type: String,
      enum: ["admin"],
      default: "admin",
      required: true,
    },

    // ========================================
    // ADMIN ROLE
    // gm = General Manager
    // admin = Administrator
    // ========================================

    role: {
      type: String,
      enum: ALLOWED_ADMIN_ROLES,
      required: true,
    },

    // ========================================
    // RESPONSIBILITIES
    // ========================================

    responsibilities: {
      type: [
        {
          type: String,
          enum: ALLOWED_RESPONSIBILITIES,
        },
      ],

      default: [],

      validate: {
        validator: function (responsibilities) {
          return (
            Array.isArray(responsibilities) &&
            new Set(responsibilities).size ===
              responsibilities.length &&
            responsibilities.every((item) =>
              ALLOWED_RESPONSIBILITIES.includes(item)
            )
          );
        },

        message:
          "Responsibilities must be valid and cannot contain duplicates.",
      },
    },

    // ========================================
    // ACCOUNT STATUS
    // ========================================

    is_verified: {
      type: Boolean,
      default: false,
    },

    is_active: {
      type: Boolean,
      default: true,
    },

    // ========================================
    // OTP VERIFICATION
    // ========================================

    otp: {
      type: String,
      default: null,
      select: false,
    },

    otp_expiry: {
      type: Date,
      default: null,
      select: false,
    },
  },

  {
    timestamps: true,
  }
);

// ============================================
// ROLE-BASED VALIDATION
// ============================================

adminSchema.pre("validate", function () {

  // GENERAL MANAGER
  // GM automatically receives all responsibilities.
  // Therefore, individual responsibilities must be empty.

  if (this.role === "gm") {
    if (
      Array.isArray(this.responsibilities) &&
      this.responsibilities.length > 0
    ) {
      this.invalidate(
        "responsibilities",
        "GM receives all responsibilities automatically."
      );
    }
  }

  // ADMINISTRATOR
  // An administrator must receive at least one responsibility.

  if (this.role === "admin") {
    if (
      !Array.isArray(this.responsibilities) ||
      this.responsibilities.length === 0
    ) {
      this.invalidate(
        "responsibilities",
        "Assign at least one responsibility to this administrator."
      );
    }
  }

});

// ============================================
// DATABASE INDEXES
// ============================================

// Helps retrieve active accounts by role.
adminSchema.index({
  role: 1,
  is_active: 1,
});

// ============================================
// EXPORT MODEL
// ============================================

const Admin = mongoose.model("Admin", adminSchema);

module.exports = Admin;

// Export constants if needed elsewhere.
module.exports.ALLOWED_ADMIN_ROLES =
  ALLOWED_ADMIN_ROLES;

module.exports.ALLOWED_RESPONSIBILITIES =
  ALLOWED_RESPONSIBILITIES;
