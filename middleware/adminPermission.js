
const ROLE_PERMISSIONS = require("../config/adminPermissions");

function requirePermission(moduleName, action) {
  return (req, res, next) => {
    try {
      if (!req.admin) {
        return res.status(401).json({
          status: "unauthorized",
          message: "Admin authentication required",
        });
      }

      const roles = req.admin.roles || [];

      // GM gets full access.
      if (roles.includes("gm")) {
        return next();
      }

      const hasPermission = roles.some((role) => {
        const permissions = ROLE_PERMISSIONS[role];

        return (
          permissions &&
          permissions[moduleName] &&
          permissions[moduleName].includes(action)
        );
      });

      if (!hasPermission) {
        return res.status(403).json({
          status: "permission_denied",
          message: "You do not have permission to perform this action.",
        });
      }

      next();
    } catch (error) {
      console.error("Permission middleware error:", error);

      return res.status(500).json({
        status: "error",
        message: "Permission verification failed",
      });
    }
  };
}

module.exports = requirePermission;
