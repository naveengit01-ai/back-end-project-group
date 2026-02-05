// models/JobApplication.js
const mongoose = require("mongoose");

const jobApplicationSchema = new mongoose.Schema(
  {
    job_id: { type: mongoose.Schema.Types.ObjectId, ref: "Job" },
    job_title: String,

    first_name: String,
    last_name: String,
    email: String,
    phone: String,
    location: String,

    resume_link: String,
    message: String
  },
  { timestamps: true }
);

module.exports = mongoose.model("JobApplication", jobApplicationSchema);
