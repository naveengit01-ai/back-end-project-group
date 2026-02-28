const axios = require("axios");

exports.chat = async (req, res) => {
  try {
    const response = await axios.post(
      "http://127.0.0.1:8000/chat",
      {
        user: req.user,
        message: req.body.message
      }
    );
    res.json(response.data);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ reply: "AI service unavailable" });
  }
};