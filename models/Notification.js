const mongoose = require("mongoose");

const NotificationSchema = new mongoose.Schema(
  {
    type: String,
    message: String,
    related_id: mongoose.Schema.Types.ObjectId
  },
  { timestamps: true }
);

module.exports = mongoose.model("Notification", NotificationSchema);
