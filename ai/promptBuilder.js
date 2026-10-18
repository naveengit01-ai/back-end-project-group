const Donation = require("../models/Donation");

/**
 * Builds ChatGPT-style context for the logged-in user
 */
async function buildUserContext(user) {
  const context = [];

  // 👤 Basic info
  context.push(`User name is ${user.first_name} ${user.last_name}.`);
  context.push(`User email is ${user.email}.`);
  context.push(`User role is ${user.user_type}.`);

  // ❤️ Donations
  const donations = await Donation.countDocuments({
    donor_email: user.email,
  });
  context.push(`User has made ${donations} donations.`);

  // 🚚 Rider rides
  if (user.user_type === "rider") {
    const rides = await Donation.countDocuments({
      rider_email: user.email,
    });
    context.push(`User has completed ${rides} rides.`);
  }

  return context.join(" ");
}

module.exports = { buildUserContext };