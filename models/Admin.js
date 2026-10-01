const adminSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true
    },

    email: {
      type: String,
      required: true,
      unique: true
    },

    password: {
      type: String,
      required: true
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
      required: true,
      unique: true
    },

    profile_image: {
      type: String,
      default: ""
    },

    user_type: {
      type: String,
      required: true
    },

    is_verified: {
      type: Boolean,
      default: false
    },

    is_active: {
      type: Boolean,
      default: true
    },

    otp: {
      type: String,
      default: null
    },

    otp_expiry: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

const Admin = mongoose.model("Admin", adminSchema);