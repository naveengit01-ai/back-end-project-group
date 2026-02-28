const axios = require("axios");
const { buildUserContext } = require("../utils/promptBuilder");

const LLM_URL = "https://llm-model-t322.onrender.com/chat";
const LLM_TIMEOUT = 8000; // 8 sec max

exports.chat = async (req, res) => {
  try {
    const { message } = req.body;
    const user = req.user;

    if (!message || !message.trim()) {
      return res.json({
        reply: "Please type a message 🙂"
      });
    }

    const text = message.toLowerCase();

    /* ===============================
       1️⃣ INSTANT RULE REPLIES (NO AI)
    =============================== */
    if (["hi", "hello", "hey"].includes(text)) {
      return res.json({
        reply: `Hi ${user.first_name || "there"} 👋 How can I help you today?`
      });
    }

    if (text.includes("login issue")) {
      return res.json({
        reply:
          "If you face login issues:\n1️⃣ Check email & password\n2️⃣ Verify OTP\n3️⃣ Make sure your role is correct\n4️⃣ Try logout & login again"
      });
    }

    if (text.includes("signup") || text.includes("register")) {
      return res.json({
        reply:
          "Signup steps:\n1️⃣ Fill all fields\n2️⃣ Verify OTP sent to email\n3️⃣ Login using the same role you selected"
      });
    }

    /* ===============================
       2️⃣ BUILD USER CONTEXT (SAFE)
    =============================== */
    let context = "";
    try {
      context = await buildUserContext(user);
    } catch (dbErr) {
      console.warn("⚠️ Context build failed:", dbErr.message);
    }

    /* ===============================
       3️⃣ CALL PYTHON LLM (SAFE)
    =============================== */
    try {
      const llmRes = await axios.post(
        LLM_URL,
        {
          user,
          message,
          context
        },
        {
          timeout: LLM_TIMEOUT,
          headers: { "Content-Type": "application/json" }
        }
      );

      if (llmRes?.data?.reply) {
        return res.json({ reply: llmRes.data.reply });
      }

      throw new Error("Empty LLM reply");
    } catch (llmErr) {
      console.error("⚠️ LLM failed:", llmErr.message);

      /* ===============================
         4️⃣ FINAL FALLBACK (NO 500)
      =============================== */
      return res.json({
        reply:
          "I understand your question 👍\nCurrently I can help with:\n• Your profile\n• Donations\n• Jobs\n• Login & signup help\n\nMore features coming soon 🚀"
      });
    }

  } catch (err) {
    console.error("🔥 AI CHAT CRASH:", err.message);

    // ABSOLUTE LAST SHIELD
    return res.json({
      reply: "Something went wrong, but I’m still here 🙂 Please try again."
    });
  }
};