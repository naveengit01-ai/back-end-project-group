const Donation = require("../models/Donation");
const JobApplication = require("../models/JobApplication");
const { buildUserContext } = require("./promptBuilder");

exports.chat = async (req, res) => {
  try {
    const user = req.user;
    const message = req.body.message.toLowerCase();

    await buildUserContext(user); // future-proof

    if (message.includes("my name")) {
      return res.json({
        reply: `Your name is ${user.first_name || "User"}`
      });
    }

    if (message.includes("my email")) {
      return res.json({
        reply: `Your registered email is ${user.email}`
      });
    }

    if (message.includes("my donations")) {
      const count = await Donation.countDocuments({
        donor_email: user.email
      });

      return res.json({
        reply: `You have made ${count} donations`
      });
    }

    if (user.role === "rider" && message.includes("my rides")) {
      const rides = await Donation.countDocuments({
        rider_email: user.email
      });

      return res.json({
        reply: `You have completed ${rides} rides`
      });
    }

    if (message.includes("job")) {
      const apps = await JobApplication.countDocuments({
        email: user.email
      });

      return res.json({
        reply: `You have applied for ${apps} jobs`
      });
    }

    return res.json({
      reply: "I understand you 🙂 Ask me about your profile, donations, or jobs."
    });

  } catch (err) {
    console.error("AI chat error:", err);
    res.status(500).json({ reply: "AI error occurred" });
  }
};