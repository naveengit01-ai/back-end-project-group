const mongoose = require("mongoose");

const JobApplicationSchema = new mongoose.Schema(
  {
    job_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Job",
      required: true
    },

    job_title: {
      type: String,
      required: true
    },

    first_name: String,
    last_name: String,
    email: String,
    phone: String,
    location: String,

    resume_link: String,
    message: String,

    status: {
      type: String,
      enum: [
        "pending",
        "interview_scheduled",
        "selected",
        "rejected"
      ],
      default: "pending"
    },

    interview: {
      date: String,
      time: String,
      mode: String,
      location: String
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("JobApplication", JobApplicationSchema);
