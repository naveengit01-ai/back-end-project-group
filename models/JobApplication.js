const mongoose = require("mongoose");

const JobApplicationSchema = new mongoose.Schema(
  {
    job_id: mongoose.Schema.Types.ObjectId,
    job_title: String,

    first_name: String,
    last_name: String,
    email: String,
    phone: String,
    location: String,

    resume_link: String,
    message: String,

    status: {
      type: String,
      enum: ["pending", "accepted", "rejected"],
      default: "pending"
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("JobApplication", JobApplicationSchema);
