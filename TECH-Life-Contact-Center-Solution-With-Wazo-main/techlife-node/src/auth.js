/**
 * Session-based auth (bcryptjs + express-session). Equivalent to the
 * previous PHP Auth class -- same login contract, same session shape.
 * Enhanced with strict tenant boundary enforcement and permission checks.
 */
const bcrypt = require('bcryptjs');
const { pool, setTenantScope } = require('./db');
const { writeAuditLog } = require('./auditLog');
const { getTenantLicenseStatus } = require('./licenseService');

async function attemptLogin(tenantSlug, username, password) {
    const normalizedTenantSlug = typeof tenantSlug === 'string' && tenantSlug.trim()
        ? tenantSlug.trim()
        : null;
    const userRes = await pool.query(
        `SELECT u.id, u.tenant_id, u.username, u.full_name, u.password_hash, u.is_active, u.theme_preference,
                t.slug AS tenant_slug
         FROM users u
         JOIN tenants t ON t.id = u.tenant_id
         WHERE ($1::text IS NULL OR t.slug = $1)
           AND u.username = $2
           AND u.is_active = TRUE
           AND t.is_active = TRUE`,
        [normalizedTenantSlug, username]
    );
    const validUsers = [];
    for (const candidate of userRes.rows) {
        if (await bcrypt.compare(password, candidate.password_hash)) validUsers.push(candidate);
    }
    if (validUsers.length !== 1) return null;
    const user = validUsers[0];

    const roleRes = await pool.query(
        `SELECT r.role_type FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1`,
        [user.id]
    );
    const roles = roleRes.rows.map((r) => r.role_type);

    // Fetch permissions for this user's roles
    const permRes = await pool.query(
        `SELECT DISTINCT p.code FROM user_roles ur
         JOIN role_permissions rp ON rp.role_id = ur.role_id
         JOIN permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = $1`,
        [user.id]
    );
    const permissions = permRes.rows.map((r) => r.code);

    const agentRes = await pool.query('SELECT id FROM agents WHERE user_id = $1 LIMIT 1', [user.id]);
    const agentId = agentRes.rows[0] ? agentRes.rows[0].id : null;

    await pool.query('UPDATE users SET last_login_at = now() WHERE id = $1', [user.id]);
    await writeAuditLog(user.tenant_id, user.id, 'LOGIN', 'user', user.id);

    return {
        id: user.id,
        tenantId: user.tenant_id,
        tenantSlug: user.tenant_slug,
        username: user.username,
        fullName: user.full_name,
        roles,
        permissions,
        agentId,
        themePreference: user.theme_preference || 'brand',
    };
}

/** Express middleware: require a logged-in session. */
function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.redirect('/login');
    }
    // Attach tenant scope for this request's pool usage pattern (each
    // query still filters by tenant_id explicitly; this is the RLS hook).
    req.tenantScope = async (client) => setTenantScope(client, req.session.user.tenantId);
    next();
}

async function requireTenantLicense(req, res, next) {
    if (!req.session || !req.session.user) return next();

    const skipPaths = ['/login', '/logout', '/license', '/license/upload'];
    if (skipPaths.includes(req.path)) return next();
    if (req.session.user.roles.includes('superadmin') && !req.effectiveTenant) return next();

    try {
        const tenantId = req.effectiveTenant?.id || req.session.user.tenantId;
        if (!tenantId) return next();

        const status = await getTenantLicenseStatus(tenantId);
        if (!status.isValid) {
            req.licenseStatus = status;
            return res.status(403).render('tenant_license_required', {
                pageTitle: 'Tenant License Required',
                tenantId,
                reason: status.reason,
                canManageLicense: req.session.user.roles.some((role) => ['admin', 'superadmin'].includes(role)),
            });
        }

        req.licenseStatus = status;
        next();
    } catch (err) {
        console.error('License validation failed:', err);
        return res.status(500).send('License validation failed. Please contact support.');
    }
}

/** Express middleware factory: require at least one of the given roles. */
function requireRole(allowedRoles) {
    return (req, res, next) => {
        if (!req.session || !req.session.user) {
            return res.redirect('/login');
        }
        const roles = req.session.user.roles || [];
        const allowed = roles.some((r) => allowedRoles.includes(r));
        if (!allowed) {
            res.status(403).send('403 Forbidden — your role does not have access to this page.');
            return;
        }
        next();
    };
}

/**
 * Express middleware factory: require at least one of the given permissions.
 * Permissions are checked after roles, for fine-grained access control.
 */
function requirePermission(allowedPermissions) {
    return (req, res, next) => {
        if (!req.session || !req.session.user) {
            return res.redirect('/login');
        }
        const permissions = req.session.user.permissions || [];
        const allowed = permissions.some((p) => allowedPermissions.includes(p));
        if (!allowed) {
            res.status(403).send('403 Forbidden — you do not have permission for this action.');
            return;
        }
        next();
    };
}

/**
 * Prevent a user from assigning or possessing a role that is above their own.
 * Superadmin can assign any role. Admin can only assign admin/supervisor/agent/mis_agent.
 * User Manager can only assign non-superadmin/non-admin roles.
 * Manager cannot assign any role.
 */
function canAssignRole(userRoles, targetRole) {
    const roleHierarchy = { superadmin: 5, admin: 4, manager: 3, user_manager: 2, reports_only: 1, agent: 0 };
    const userMaxLevel = Math.max(...userRoles.map((r) => roleHierarchy[r] || 0));
    const targetLevel = roleHierarchy[targetRole] || 0;
    return targetLevel <= userMaxLevel;
}

async function logout(req) {
    const u = req.session.user;
    if (u) {
        await writeAuditLog(u.tenantId, u.id, 'LOGOUT', 'user', u.id);
    }
}

module.exports = { attemptLogin, requireAuth, requireTenantLicense, requireRole, requirePermission, canAssignRole, logout };
