const mongoose = require("mongoose");

/* ================= SUB HEADING ================= */
const SubHeadingSchema = new mongoose.Schema(
  {
    title: String,
    notes: String,
    code: String // optional
  },
  { _id: false }
);

/* ================= SUB TOPIC ================= */
const SubTopicSchema = new mongoose.Schema(
  {
    title: String,
    notes: String,
    code: String, // optional
    subHeadings: [SubHeadingSchema]
  },
  { _id: false }
);

/* ================= MAIN TOPIC ================= */
const MainTopicSchema = new mongoose.Schema(
  {
    title: String,
    notes: String,
    code: String, // optional
    subTopics: [SubTopicSchema]
  },
  { _id: false }
);

/* ================= CONTENT ================= */
const YoutubeContentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true
    },

    embedCode: {
      type: String // optional (can be empty)
    },

    mainTopics: {
      type: [MainTopicSchema],
      default: []
    },

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
