const mongoose = require("mongoose");

const ALLOWED_ADMIN_ROLES = [
  "gm",
  "customersupport",
  "marketing",
  "finance",
  "operations",
  "hr",
  "admin",
];

const adminSchema = new mongoose.Schema(
  {
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

    password: {
      type: String,
      required: true,
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
    },

    user_type: {
      type: String,
      required: true,
      enum: ["admin"],
      default: "admin",
    },

    roles: {
      type: [
        {
          type: String,
          enum: ALLOWED_ADMIN_ROLES,
        },
      ],
      default: ["customersupport"],
      required: true,
      validate: {
        validator: function (roles) {
          return (
            Array.isArray(roles) &&
            roles.length > 0 &&
            new Set(roles).size === roles.length &&
            roles.every((role) => ALLOWED_ADMIN_ROLES.includes(role))
          );
        },
        message:
          "Select at least one valid role without duplicate roles.",
      },
    },

    must_change_password: {
      type: Boolean,
      default: true,
    },

    is_verified: {
      type: Boolean,
      default: false,
    },

    is_active: {
      type: Boolean,
      default: true,
    },

    otp: {
      type: String,
      default: null,
    },

    otp_expiry: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Admin", adminSchema);