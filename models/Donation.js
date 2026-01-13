const mongoose = require("mongoose");

const donationSchema = new mongoose.Schema(
  {
    donor_email: {
      type: String,
      required: true
    },

    donor_name: {
      type: String,
      required: true
    },

    item_type: {
      type: String,
      enum: ["food", "clothes", "other"],
      required: true
    },

    item_name: {
      type: String,
      required: true
    },

    quantity: {
      type: Number,
      required: true,
      min: 1
    },

    price_type: {
      type: String,
      enum: ["free", "paid"],
      required: true
    },

    price_amount: {
      type: Number,
      default: 0
    },

    // 🔥 RIDER FLOW FIELDS (MISSING BEFORE)
    rider_email: {
      type: String,
      default: null
    },

    donation_status: {
      type: String,
      enum: ["not_picked", "picked", "collected", "delivered"],
      default: "not_picked"
    },

    picked_at: Date,
    collected_at: Date,
    delivered_at: Date,

    otp: String,
    otp_expiry: Date,

    is_verified: {
      type: Boolean,
      default: false
    },

    pickup_location: {
      type: String,
      required: true
    },

    remarks: String,
    rejection_reason: String
  },
  { timestamps: true }
);

module.exports = mongoose.model("Donation", donationSchema);
