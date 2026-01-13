const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    /* AUTH */
    username: {
      type: String,
      required: true,
      unique: true,
      minlength: 6,
      trim: true
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    password: {
      type: String,
      required: true
    },

    /* BASIC INFO */
    first_name: {
      type: String,
      required: true,
      trim: true
    },

    last_name: {
      type: String,
      required: true,
      trim: true
    },

    phone: {
      type: String,
      required: true
    },

    profile_image: {
      type: String,
      default: ""
    },

    /* ROLE */
    user_type: {
      type: String,
      enum: ["user", "rider"],
      required: true
    },

    /* RIDER-SPECIFIC */
    rider_location: {
      lat: { type: Number },
      lng: { type: Number }
    },

    is_rider_approved: {
      type: Boolean,
      default: false
    },

    /* ACCOUNT STATUS */
    is_verified: {
      type: Boolean,
      default: false
    },

    is_active: {
      type: Boolean,
      default: true
    },

    /* OTP */
    otp: String,
    otp_expiry: Date,

    /* META */
    last_login: Date
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
