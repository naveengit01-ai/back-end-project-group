const mongoose = require("mongoose");

const FileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  language: { type: String, required: true },
  content: { type: String, default: "" }
});

const CodeSchema = new mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    files: [FileSchema]
  },
  { timestamps: true }
);

module.exports = mongoose.model("Code", CodeSchema);