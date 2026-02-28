const axios = require("axios");

// Replace with your deployed LLM service URL
const LLM_URL = "https://llm-model-t322.onrender.com/chat";

exports.chat = async (req, res) => {
  try {
    const { message } = req.body;
    const user = req.user || {};

    // Call the Python LLM service
    const response = await axios.post(LLM_URL, {
      user,
      message
    });

    const { reply } = response.data;

    return res.json({ reply });

  } catch (err) {
    console.error("LLM request failed:", err.message);
    return res.status(500).json({ reply: "AI service failed" });
  }
};