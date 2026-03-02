const axios = require("axios");
const { buildUserContext } = require("../ai/promptBuilder");
const User = require("../models/User"); // ✅ FIX: fetch full user from DB

// const LLM_URL = "https://llm-model-t322.onrender.com/chat";
const LLM_URL = "http://127.0.0.1:8000/chat";
const LLM_TIMEOUT = 55000; // ✅ FIX: 55 sec — handles Render cold start

exports.chat = async (req, res) => {
  try {
    const { message } = req.body;
    const tokenUser = req.user; // only has { id, role }

    if (!message || !message.trim()) {
      return res.json({ reply: "Please type a message 🙂" });
    }

    const text = message.toLowerCase().trim();

    /* ===============================
       1️⃣ INSTANT RULE REPLIES (NO AI)
    =============================== */
    if (["hi", "hello", "hey"].includes(text)) {
      return res.json({
        reply: `Hi there 👋 How can I help you today?`
      });
    }

    if (text.includes("login issue") || text.includes("cant login") || text.includes("can't login")) {
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
       2️⃣ FETCH FULL USER FROM DB ✅
    =============================== */
    let fullUser = tokenUser;
    try {
      const dbUser = await User.findById(tokenUser.id).select("-password -otp -otp_expiry");
      if (dbUser) fullUser = dbUser;
    } catch (dbErr) {
      console.warn("⚠️ User fetch failed:", dbErr.message);
    }

    /* ===============================
       3️⃣ PERSONAL QUERIES (name, email etc.)
    =============================== */
    if (text.includes("my name") || text === "what is my name" || text === "tell me my name") {
      const name = `${fullUser.first_name || ""} ${fullUser.last_name || ""}`.trim();
      return res.json({
        reply: name ? `Your name is ${name} 😊` : "Your name is not updated in your profile."
      });
    }

    if (text.includes("my email") || text === "what is my email") {
      return res.json({
        reply: `Your registered email is ${fullUser.email} 📧`
      });
    }

    if (text.includes("my role") || text.includes("what am i")) {
      return res.json({
        reply: `You are registered as a ${fullUser.user_type || fullUser.role} on DWJD.`
      });
    }

    /* ===============================
       4️⃣ BUILD USER CONTEXT (SAFE)
    =============================== */
    let context = "";
    try {
      context = await buildUserContext(fullUser);
    } catch (ctxErr) {
      console.warn("⚠️ Context build failed:", ctxErr.message);
    }

    /* ===============================
       5️⃣ CALL PYTHON LLM
    =============================== */
    try {
      const llmRes = await axios.post(
        LLM_URL,
        { user: fullUser, message, context },
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

      // ✅ Better fallback — at least answer from context if possible
      return res.json({
        reply:
          "I'm waking up from sleep 😴 Please send your message again in a few seconds — I'll be ready!"
      });
    }

  } catch (err) {
    console.error("🔥 AI CHAT CRASH:", err.message);
    return res.json({
      reply: "Something went wrong, but I'm still here 🙂 Please try again."
    });
  }
};