// models/Job.js
const mongoose = require("mongoose");

const jobSchema = new mongoose.Schema(
  {
    title: String,
    role_type: String, // Volunteer / Rider / Admin / NGO / Tech
    description: String,
    location: String,
    eligibility: String,
    is_active: { type: Boolean, default: true }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Job", jobSchema);
