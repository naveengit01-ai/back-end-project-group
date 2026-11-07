
const ROLE_PERMISSIONS = {
  gm: {
    dashboard: ["read"],
    customers: ["create", "read", "update", "delete"],
    riders: ["create", "read", "update", "delete"],
    donations: ["create", "read", "update", "delete"],
    orders: ["create", "read", "update", "delete"],
    marketing: ["create", "read", "update", "delete"],
    finance: ["create", "read", "update", "delete"],
    operations: ["create", "read", "update", "delete"],
    hr: ["create", "read", "update", "delete"],
    reports: ["read"],
    admins: ["create", "read", "update", "delete"],
    permissions: ["read", "update"],
  },

  customersupport: {
    dashboard: ["read"],
    customers: ["read", "update"],
    donations: ["read"],
    orders: ["read", "update"],
    riders: ["read"],
  },

  marketing: {
    dashboard: ["read"],
    marketing: ["create", "read", "update", "delete"],
    reports: ["read"],
  },

  finance: {
    dashboard: ["read"],
    finance: ["read", "update"],
    reports: ["read"],
  },

  operations: {
    dashboard: ["read"],
    riders: ["read", "update"],
    donations: ["read", "update"],
    orders: ["read", "update"],
  },

  hr: {
    dashboard: ["read"],
    hr: ["create", "read", "update", "delete"],
    riders: ["read"],
  },

  admin: {
    dashboard: ["read"],
  },
};

module.exports = ROLE_PERMISSIONS;
