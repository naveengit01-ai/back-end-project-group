const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
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
  sparse: true,
},

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    user_type: {
      type: String,
      enum: ["user", "rider"],
      required: true,
    },

    // Local or Google authentication
    auth_provider: {
      type: String,
      enum: ["local", "google"],
      default: "local",
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

    profile_image: {
      type: String,
      default: "",
    },

    is_verified: {
      type: Boolean,
      default: false,
    },

    // Existing email verification OTP
    otp: {
      type: String,
      default: null,
    },

    otp_expiry: {
      type: Date,
      default: null,
    },

    // Password reset fields
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
    },

    // Preserve rider approval functionality
    is_rider_approved: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// A Google ID must be unique when it exists.
// Local users do not need a Google ID.
userSchema.index(
  { google_id: 1 },
  {
    unique: true,
    partialFilterExpression: {
      google_id: { $type: "string" },
    },
  }
);

module.exports = mongoose.model("User", userSchema);