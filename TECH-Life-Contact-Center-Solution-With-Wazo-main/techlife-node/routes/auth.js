const express = require('express');
const router = express.Router();
const { attemptLogin, logout } = require('../src/auth');
const { getTenantLicenseStatus } = require('../src/licenseService');

router.get('/login', (req, res) => {
    res.render('login', { error: null, form: {} });
});

router.post('/login', async (req, res) => {
    const { tenant_slug, username, password } = req.body;
    try {
        const user = await attemptLogin(tenant_slug, username, password);
        if (!user) {
            return res.render('login', {
                error: 'Invalid username or password, or more than one tenant account matches. Enter the tenant slug under sign-in options if needed.',
                form: req.body,
            });
        }

        const licenseStatus = await getTenantLicenseStatus(user.tenantId);
        const isSuperadmin = user.roles.includes('superadmin');
        if (!licenseStatus.isValid && isSuperadmin) {
            req.session.user = user;
            return res.redirect('/superadmin');
        }
        if (!licenseStatus.isValid && user.roles.includes('admin')) {
            req.session.user = user;
            return res.redirect('/admin/license');
        }
        if (!licenseStatus.isValid) {
            return res.render('login', {
                error: `This tenant cannot access the platform until a valid license is uploaded. ${licenseStatus.reason}`,
                form: req.body,
            });
        }

        req.session.user = user;
        const roles = user.roles;
        let target = '/agent';
        if (roles.includes('superadmin')) target = '/superadmin';
        else if (roles.includes('admin')) target = '/admin';
        else if (roles.includes('supervisor')) target = '/supervisor';
        else if (roles.includes('mis_agent')) target = '/mis';
        res.redirect(target);
    } catch (e) {
        console.error(e);
        res.render('login', { error: 'Server error, please try again.', form: req.body });
    }
});

router.get('/logout', async (req, res) => {
    await logout(req);
    req.session.destroy(() => res.redirect('/login'));
});

module.exports = router;
