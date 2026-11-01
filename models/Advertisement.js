
const mongoose = require("mongoose");

const advertisementSchema = new mongoose.Schema(
  {
    // 1. BRAND / COMPANY INFORMATION
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

    // 2. ADVERTISEMENT DETAILS
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

    // Google Drive file IDs
    image_drive_file_id: {
      type: String,
      default: "",
      trim: true,
    },

    video_drive_file_id: {
      type: String,
      default: "",
      trim: true,
    },

    // 3. MEDIA CLEANUP TRACKING
    media_cleanup_status: {
      type: String,
      enum: ["pending", "processing", "completed", "failed"],
      default: "pending",
    },

    media_cleanup_attempts: {
      type: Number,
      default: 0,
    },

    media_cleanup_last_attempt_at: {
      type: Date,
      default: null,
    },

    media_cleanup_error: {
      type: String,
      default: "",
    },

    media_cleaned_at: {
      type: Date,
      default: null,
    },

    // 4. PLACEMENT
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

    // 5. CAMPAIGN SCHEDULE
    start_date: {
      type: Date,
      required: true,
    },

    end_date: {
      type: Date,
      required: true,
      validate: {
        validator: function (value) {
          return !this.start_date || value > this.start_date;
        },
        message: "End date must be after the start date.",
      },
    },

    // 6. PAYMENT
    amount_paid: {
      type: Number,
      required: true,
      min: 0,
    },

    approved_amount: {
      type: Number,
      min: 1,
      default: null,
    },

    currency: {
      type: String,
      default: "INR",
      enum: ["INR", "USD", "EUR", "GBP"],
    },

    payment_status: {
      type: String,
      enum: ["pending", "paid", "failed", "refunded"],
      default: "pending",
    },

    // Razorpay Payment Link fields
    payment_link_id: {
      type: String,
      default: "",
      trim: true,
    },

    payment_link_url: {
      type: String,
      default: "",
      trim: true,
    },

    payment_link_sent_at: {
      type: Date,
      default: null,
    },

    // Verified payment reference
    payment_reference: {
      type: String,
      default: "",
      trim: true,
    },

    payment_paid_at: {
      type: Date,
      default: null,
    },

    // 7. COLLABORATION
    collaboration_type: {
      type: String,
      enum: [
        "paid_promotion",
        "sponsorship",
        "brand_partnership",
      ],
      default: "paid_promotion",
    },

    // 8. APPROVAL
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

    // 9. ACTIVATION
    is_active: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// 10. INDEXES

advertisementSchema.index({
  status: 1,
  is_active: 1,
  start_date: 1,
  end_date: 1,
});

advertisementSchema.index({
  brand_name: 1,
});

advertisementSchema.index({
  payment_link_id: 1,
});

advertisementSchema.index({
  payment_status: 1,
});

advertisementSchema.index({
  end_date: 1,
  media_cleanup_status: 1,
});

module.exports = mongoose.model(
  "Advertisement",
  advertisementSchema
);
