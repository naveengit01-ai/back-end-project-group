const mongoose = require("mongoose");

const becomeRiderSchema = new mongoose.Schema(
  {
    // Rider's personal information
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

    // Email submitted by the visitor
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true,
    },

    // Mobile number submitted after email eligibility check
    phone: {
      type: String,
      required: true,
      trim: true,
    },

    // Request processing status
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

    // Email eligibility check
    email_checked: {
      type: Boolean,
      default: false,
    },

    // Customer Support review information
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

    // Reference to the rider account created from this request
    created_user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // Account creation timestamp
    account_created_at: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// Reuse the existing model if it has already been registered.
const BecomeRider =
  mongoose.models.BecomeRider ||
  mongoose.model("BecomeRider", becomeRiderSchema);

module.exports = BecomeRider;