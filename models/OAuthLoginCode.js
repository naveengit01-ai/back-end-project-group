const mongoose = require("mongoose");

const oauthLoginCodeSchema = new mongoose.Schema(
  {
    code_hash: {
      type: String,
      required: true,
      unique: true,
    },

    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    expires_at: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

oauthLoginCodeSchema.index(
  { expires_at: 1 },
  { expireAfterSeconds: 0 }
);

module.exports = mongoose.model(
  "OAuthLoginCode",
  oauthLoginCodeSchema
);