
const mongoose = require("mongoose");
const crypto = require("crypto");

const occasionDonationSchema = new mongoose.Schema(
  {
    referenceCode: {
      type: String,
      unique: true,
      index: true,
    },

    donor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    donorSnapshot: {
      name: { type: String, default: "" },
      email: { type: String, default: "" },
      phone: { type: String, default: "" },
    },

    occasionType: {
      type: String,
      required: true,
      enum: [
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
      ],
    },

    occasionTitle: {
      type: String,
      trim: true,
      maxlength: 100,
      default: "",
    },

    occasionDate: {
      type: Date,
      required: true,
    },

    scheduledWishTime: {
      type: String,
      required: true,
      match: /^([01]\d|2[0-3]):([0-5]\d)$/,
    },

    timeZone: {
      type: String,
      default: "Asia/Kolkata",
    },

    scheduledAt: {
      type: Date,
      required: true,
      index: true,
    },

    recipientName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },

    recipientEmail: {
      type: String,
      trim: true,
      lowercase: true,
      maxlength: 150,
      default: "",
    },

    recipientPhone: {
      type: String,
      trim: true,
      maxlength: 20,
      default: "",
    },

    recipientContactConsent: {
      type: Boolean,
      required: true,
      default: false,
    },

    dedicationName: {
      type: String,
      trim: true,
      maxlength: 100,
      default: "",
    },

    donorMessage: {
      type: String,
      trim: true,
      maxlength: 1000,
      default: "",
    },

    amount: {
      type: Number,
      required: true,
      min: 1,
      max: 1000000,
    },

    currency: {
      type: String,
      enum: ["INR"],
      default: "INR",
    },

    media: [
      {
        driveFileId: {
          type: String,
          required: true,
        },

        url: {
          type: String,
          required: true,
        },

        name: {
          type: String,
          default: "",
        },

        mimeType: {
          type: String,
          required: true,
        },

        size: {
          type: Number,
          required: true,
        },

        resourceType: {
          type: String,
          enum: ["image", "video"],
          required: true,
        },
      },
    ],

    paymentStatus: {
      type: String,
      enum: [
        "created",
        "pending",
        "paid",
        "refund_pending",
        "refunded",
        "refund_failed",
      ],
      default: "created",
      index: true,
    },

    razorpayOrderId: {
      type: String,
      default: "",
      index: true,
    },

    razorpayPaymentId: {
      type: String,
      default: "",
      index: true,
    },

    razorpaySignature: {
      type: String,
      default: "",
    },

    paidAt: {
      type: Date,
      default: null,
    },

    refundId: {
      type: String,
      default: "",
    },

    refundedAt: {
      type: Date,
      default: null,
    },

    refundError: {
      type: String,
      default: "",
    },

    adminStatus: {
      type: String,
      enum: [
        "awaiting_payment",
        "pending_review",
        "approved",
        "rejected",
      ],
      default: "awaiting_payment",
      index: true,
    },

    rejectionReason: {
      type: String,
      default: "",
      maxlength: 1000,
    },

    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },

    reviewedAt: {
      type: Date,
      default: null,
    },

    // Existing greeting delivery workflow
    greetingStatus: {
      type: String,
      enum: [
        "not_scheduled",
        "scheduled",
        "sending",
        "sent",
        "failed",
        "cancelled",
      ],
      default: "not_scheduled",
      index: true,
    },

    greetingSentAt: {
      type: Date,
      default: null,
    },

    greetingAttempts: {
      type: Number,
      default: 0,
    },

    greetingLastError: {
      type: String,
      default: "",
    },

    // =========================================
    // UNIQUE WISHES LINK
    // =========================================

    // Store only the SHA-256 hash of the public token.
    // Never store the original token in MongoDB.
    wishAccessTokenHash: {
      type: String,
      default: undefined,
      unique: true,
      sparse: true,
      index: true,
    },
  wishAccessTokenEncrypted: {
  type: String,
  default: undefined,
  select: false,
},

    // =========================================
    // WISHES EMAIL DELIVERY
    // =========================================

    wishEmailStatus: {
      type: String,
      enum: [
        "not_created",
        "pending",
        "sending",
        "sent",
        "failed",
      ],
      default: "not_created",
      index: true,
    },

    wishEmailScheduledAt: {
      type: Date,
      default: null,
      index: true,
    },

    wishEmailSentAt: {
      type: Date,
      default: null,
    },

    wishEmailAttempts: {
      type: Number,
      default: 0,
    },

    wishEmailLastError: {
      type: String,
      default: "",
      maxlength: 2000,
    },

    // =========================================
    // WISHES PAGE VISIBILITY
    // =========================================

    wishPageStatus: {
      type: String,
      enum: [
        "locked",
        "published",
        "expired",
        "disabled",
      ],
      default: "locked",
      index: true,
    },

    wishPagePublishedAt: {
      type: Date,
      default: null,
    },

    wishPageExpiresAt: {
      type: Date,
      default: null,
    },

    termsAccepted: {
      type: Boolean,
      required: true,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// =========================================
// VALIDATION AND REFERENCE CODE
// =========================================

occasionDonationSchema.pre("validate", function () {
  if (!this.referenceCode) {
    this.referenceCode =
      `DWJD-OD-${Date.now().toString(36).toUpperCase()}-` +
      `${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  }

  if (!this.recipientEmail && !this.recipientPhone) {
    this.invalidate(
      "recipientEmail",
      "Recipient email or phone is required."
    );
  }

  if (!this.recipientContactConsent) {
    this.invalidate(
      "recipientContactConsent",
      "Recipient contact consent is required."
    );
  }

  if (!this.termsAccepted) {
    this.invalidate(
      "termsAccepted",
      "Terms acceptance is required."
    );
  }
});

module.exports = mongoose.model(
  "OccasionDonation",
  occasionDonationSchema
);
