// Node backend (aiController.js)
const axios = require("axios");

exports.chat = async (req, res) => {
  try {
    const response = await axios.post(
      "http://localhost:8000/chat",
      {
        user: req.user,
        message: req.body.message
      }
    );

    res.json({ reply: response.data.reply });

  } catch (err) {
    console.error("LLM error:", err.message);
    res.status(500).json({ reply: "AI service unavailable" });
  }
};