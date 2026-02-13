const mongoose = require("mongoose");

const youtubeContentSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    embedCode: String,
    views: {
      type: Number,
      default: 0
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("YoutubeContent", youtubeContentSchema);
