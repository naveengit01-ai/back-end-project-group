
const mongoose = require("mongoose");

const becomeRiderSchema = new mongoose.Schema(
  {
    // ========================================
    // EXISTING REGISTERED USER REFERENCE
    // ========================================

    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    // ========================================
    // RIDER PERSONAL INFORMATION
    // ========================================

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

    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true,
    },

    phone: {
      type: String,
      required: true,
      trim: true,
    },

    profile_image: {
      type: String,
      default: "",
    },

    // ========================================
    // EMAIL ELIGIBILITY CHECK
    // ========================================

    email_checked: {
      type: Boolean,
      default: false,
    },

    // ========================================
    // APPLICATION STATUS
    // ========================================

    status: {
      type: String,
      enum: [
        "pending",
        "under_review",
        "approved",
        "rejected",
        "account_created",
      ],
      default: "pending",
      required: true,
    },

    // ========================================
    // ADMIN REVIEW INFORMATION
    // ========================================

    reviewed_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },

    reviewed_at: {
      type: Date,
      default: null,
    },

    rejection_reason: {
      type: String,
      default: "",
      trim: true,
    },

    // ========================================
    // RIDER ACCOUNT CONVERSION
    // ========================================

    created_user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    account_created_at: {
      type: Date,
      default: null,
    },

    // ========================================
    // EMAIL NOTIFICATION TRACKING
    // ========================================

    notification_status: {
      type: String,
      enum: [
        "not_sent",
        "sent",
        "failed",
      ],
      default: "not_sent",
    },

    notification_sent_at: {
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

// Find applications belonging to a registered user
becomeRiderSchema.index({
  user_id: 1,
  createdAt: -1,
});

// Admin application listing
becomeRiderSchema.index({
  status: 1,
  createdAt: -1,
});

// Email search
becomeRiderSchema.index({
  email: 1,
});

// ========================================
// EXPORT MODEL
// ========================================

const BecomeRider =
  mongoose.models.BecomeRider ||
  mongoose.model("BecomeRider", becomeRiderSchema);

module.exports = BecomeRider;
