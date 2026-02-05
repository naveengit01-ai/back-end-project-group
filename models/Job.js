const mongoose = require("mongoose");

const JobSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    location: String,
    role_type: String,
    is_active: { type: Boolean, default: true }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Job", JobSchema);
