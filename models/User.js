const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      minlength: 6
    },

    first_name: {
      type: String,
      required: true
    },
    last_name: {
      type: String,
      required: true
    },
    phone: {
      type: String,
      required: true
    },
    email: {
      type: String,
      required: true,
      unique: true
    },
    user_type: {
      type: String,
      enum: ["rider", "user"],
      required: true
    },
    password: {
      type: String,
      required: true
    },

    rider_location: {
      lat: Number,
      lng: Number
    },

    otp: String,
    otp_expiry: Date,
    is_verified: {
      type: Boolean,
      default: false
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
