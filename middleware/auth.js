
const jwt = require("jsonwebtoken");
const User = require("../models/User");

module.exports = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Unauthorized. Please login",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    // 1. Verify JWT signature and expiry
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    if (!decoded.id) {
      return res.status(401).json({
        error: "Invalid authentication token",
      });
    }

    // 2. Fetch current account from MongoDB
    const user = await User.findById(decoded.id).select(
      "user_type token_version is_verified is_rider_approved"
    );

    if (!user) {
      return res.status(401).json({
        error: "Account not found",
      });
    }

    // 3. Check session version
    const currentVersion = user.token_version ?? 0;

    if (decoded.token_version !== currentVersion) {
      return res.status(401).json({
        error: "Session expired. Please login again.",
        code: "TOKEN_VERSION_MISMATCH",
      });
    }

    // 4. Check whether the account role has changed
    if (decoded.role !== user.user_type) {
      return res.status(401).json({
        error: "Account role changed. Please login again.",
        code: "ROLE_CHANGED",
      });
    }

    // 5. Check account verification
    if (!user.is_verified) {
      return res.status(403).json({
        error: "Account is not verified",
      });
    }

    // 6. Check rider approval
    if (
      user.user_type === "rider" &&
      user.is_rider_approved !== true
    ) {
      return res.status(403).json({
        error: "Rider account is not approved",
      });
    }

    // 7. Attach current authenticated account
    req.user = {
      id: user._id.toString(),
      role: user.user_type,
      token_version: currentVersion,
    };

    return next();

  } catch (err) {
    console.error("JWT authentication error:", err.message);

    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
};
