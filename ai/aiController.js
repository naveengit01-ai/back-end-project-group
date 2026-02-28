const axios = require("axios");

const LLM_URL = "https://llm-model-t322.onrender.com/chat";

exports.chat = async (req, res) => {
  try {
    const { message } = req.body;
    const user = req.user;

    if (!message) {
      return res.status(400).json({
        reply: "Message is required"
      });
    }

    // 🔍 DEBUG LOG (VERY IMPORTANT)
    console.log("➡️ Sending to LLM:", {
      user: {
        email: user?.email,
        role: user?.role || user?.user_type
      },
      message
    });

    const llmResponse = await axios.post(
      LLM_URL,
      {
        user,
        message
      },
      {
        timeout: 10000, // prevent hanging
        headers: {
          "Content-Type": "application/json"
        }
      }
    );

    console.log("✅ LLM replied:", llmResponse.data);

    return res.json({
      reply: llmResponse.data.reply
    });

  } catch (err) {
    console.error("❌ LLM CALL FAILED");

    if (err.response) {
      console.error("STATUS:", err.response.status);
      console.error("DATA:", err.response.data);
    } else {
      console.error("ERROR:", err.message);
    }

    return res.status(500).json({
      reply: "AI service is temporarily unavailable"
    });
  }
};