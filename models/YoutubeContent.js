const mongoose = require("mongoose");

const YoutubeContentSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    embedCode: String,

    views: {
      type: Number,
      default: 0
    },

    is_active: {
      type: Boolean,
      default: true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("YoutubeContent", YoutubeContentSchema);
