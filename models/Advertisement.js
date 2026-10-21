const mongoose = require("mongoose");

const advertisementSchema = new mongoose.Schema(
  {
    // ========================================
    // 1. BRAND / COMPANY INFORMATION
    // ========================================

    brand_name: {
      type: String,
      required: true,
      trim: true,
    },

    company_name: {
      type: String,
      required: true,
      trim: true,
    },

    contact_person: {
      type: String,
      required: true,
      trim: true,
    },

    contact_email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    },

    contact_phone: {
      type: String,
      required: true,
      trim: true,
    },

    company_website: {
      type: String,
      trim: true,
      default: "",
    },

    // ========================================
    // 2. ADVERTISEMENT DETAILS
    // ========================================

    title: {
      type: String,
      required: true,
      trim: true,
    },

    description: {
      type: String,
      required: true,
      trim: true,
    },

    promotion_type: {
      type: String,
      enum: [
        "banner",
        "sponsored_post",
        "video",
        "product_promotion",
        "brand_awareness",
      ],
      required: true,
    },

    image_url: {
      type: String,
      default: "",
      trim: true,
    },

    video_url: {
      type: String,
      default: "",
      trim: true,
    },

    target_url: {
      type: String,
      default: "",
      trim: true,
    },

    // ========================================
    // 3. ADVERTISEMENT PLACEMENT
    // ========================================

    placement: {
      type: String,
      enum: [
        "home_page",
        "donation_page",
        "pickup_page",
        "rider_dashboard",
        "all_pages",
      ],
      default: "home_page",
    },

    // ========================================
    // 4. CAMPAIGN SCHEDULE
    // ========================================

    start_date: {
      type: Date,
      required: true,
    },

    end_date: {
      type: Date,
      required: true,
      validate: {
        validator: function (value) {
          return (
            !this.start_date ||
            value > this.start_date
          );
        },
        message: "End date must be after the start date.",
      },
    },

    // ========================================
    // 5. COLLABORATION & PAYMENT
    // ========================================

    amount_paid: {
      type: Number,
      required: true,
      min: 0,
    },

    currency: {
      type: String,
      default: "INR",
      enum: ["INR", "USD", "EUR", "GBP"],
    },

    payment_status: {
      type: String,
      enum: [
        "pending",
        "paid",
        "failed",
        "refunded",
      ],
      default: "pending",
    },

    payment_reference: {
      type: String,
      default: "",
      trim: true,
    },

    collaboration_type: {
      type: String,
      enum: [
        "paid_promotion",
        "sponsorship",
        "brand_partnership",
      ],
      default: "paid_promotion",
    },

    // ========================================
    // 6. CAMPAIGN APPROVAL
    // ========================================

    status: {
      type: String,
      enum: [
        "pending",
        "approved",
        "rejected",
        "completed",
      ],
      default: "pending",
    },

    rejection_reason: {
      type: String,
      default: "",
      trim: true,
    },

    reviewed_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },

    reviewed_at: {
      type: Date,
      default: null,
    },

    // ========================================
    // 7. ADVERTISEMENT CONTROL
    // ========================================

    is_active: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// ========================================
// INDEXES
// ========================================

advertisementSchema.index({
  status: 1,
  is_active: 1,
  start_date: 1,
  end_date: 1,
});

advertisementSchema.index({
  brand_name: 1,
});

module.exports = mongoose.model(
  "Advertisement",
  advertisementSchema
);