const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pool } = require('./db');
let licenseTableReady;

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    if (value && typeof value === 'object') {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
    }
    return JSON.stringify(value);
}

function normalizeMac(value) {
    return String(value || '').replace(/[:-]/g, '').toLowerCase();
}

function licensePublicKey() {
    const keyPath = process.env.LICENSE_PUBLIC_KEY_PATH || path.join(__dirname, '..', 'license_public.pem');
    if (!fs.existsSync(keyPath)) {
        throw new Error(`License public key not found at ${keyPath}`);
    }
    return fs.readFileSync(keyPath, 'utf8');
}

async function validateLicenseDocument(licenseKey, tenantId) {
    let document;
    try {
        document = JSON.parse(licenseKey);
    } catch {
        return { isValid: false, status: 'invalid', reason: 'License must be a signed JSON license file.' };
    }

    const payload = document && document.payload;
    if (!payload || typeof payload !== 'object' || typeof document.signature !== 'string') {
        return { isValid: false, status: 'invalid', reason: 'License file format is invalid.' };
    }

    let signature;
    try {
        signature = Buffer.from(document.signature, 'base64');
        if (signature.length !== 64 || signature.toString('base64') !== document.signature) {
            throw new Error('Invalid signature encoding.');
        }
        const validSignature = crypto.verify(
            null,
            Buffer.from(canonicalJson(payload), 'utf8'),
            licensePublicKey(),
            signature
        );
        if (!validSignature) {
            return { isValid: false, status: 'invalid', reason: 'License signature is invalid.' };
        }
    } catch (error) {
        return { isValid: false, status: 'invalid', reason: `License signature could not be verified: ${error.message}` };
    }

    const requiredFields = ['tenant_slug', 'server_ip', 'domain_id', 'server_mac', 'issued_at', 'expires_at'];
    if (payload.version !== 1
        || requiredFields.some((field) => typeof payload[field] !== 'string' || !payload[field].trim())
        || !Number.isSafeInteger(payload.max_users)
        || payload.max_users < 1) {
        return { isValid: false, status: 'invalid', reason: 'License is missing required fields or has an invalid user limit.' };
    }

    const tenantRes = await pool.query('SELECT slug FROM tenants WHERE id = $1', [tenantId]);
    if (!tenantRes.rows[0] || tenantRes.rows[0].slug !== payload.tenant_slug) {
        return { isValid: false, status: 'invalid', reason: 'This license was issued for a different tenant.' };
    }

    const expectedBindings = {
        server_ip: process.env.LICENSE_SERVER_IP,
        domain_id: process.env.LICENSE_DOMAIN_ID,
        server_mac: process.env.LICENSE_SERVER_MAC,
    };
    const missingBindings = Object.entries(expectedBindings)
        .filter(([, value]) => !value || !value.trim())
        .map(([key]) => key);
    if (missingBindings.length) {
        return {
            isValid: false,
            status: 'invalid',
            reason: `Server license binding is not configured: ${missingBindings.join(', ')}.`,
        };
    }

    if (payload.server_ip !== expectedBindings.server_ip.trim()
        || payload.domain_id !== expectedBindings.domain_id.trim()
        || normalizeMac(payload.server_mac) !== normalizeMac(expectedBindings.server_mac)) {
        return { isValid: false, status: 'invalid', reason: 'License server IP, domain ID, or MAC address does not match this server.' };
    }

    const now = Date.now();
    const issuedAt = Date.parse(payload.issued_at);
    const expiresAt = Date.parse(payload.expires_at);
    if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
        return { isValid: false, status: 'invalid', reason: 'License validity dates are invalid.' };
    }
    if (now < issuedAt) {
        return { isValid: false, status: 'not_yet_valid', reason: 'License validity has not started yet.' };
    }
    if (now >= expiresAt) {
        return { isValid: false, status: 'expired', reason: 'This tenant license has expired.' };
    }

    return { isValid: true, status: 'active', reason: 'License is active.', payload };
}

async function ensureLicenseTable() {
    if (!licenseTableReady) {
        licenseTableReady = (async () => {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS tenant_licenses (
                    id SERIAL PRIMARY KEY,
                    tenant_id INTEGER NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
                    license_key TEXT,
                    license_file_name TEXT,
                    license_status VARCHAR(32) NOT NULL DEFAULT 'inactive',
                    is_active BOOLEAN NOT NULL DEFAULT FALSE,
                    valid_from TIMESTAMPTZ,
                    valid_to TIMESTAMPTZ,
                    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW(),
                    notes TEXT
                )
            `);

            const columns = ['license_key', 'license_file_name', 'license_status', 'is_active', 'valid_from', 'valid_to', 'uploaded_at', 'notes'];
            for (const column of columns) {
                await pool.query(`ALTER TABLE tenant_licenses ADD COLUMN IF NOT EXISTS ${column} ${column === 'license_status' ? 'VARCHAR(32)' : column === 'is_active' ? 'BOOLEAN' : column === 'valid_from' || column === 'valid_to' || column === 'uploaded_at' ? 'TIMESTAMPTZ' : column === 'notes' ? 'TEXT' : 'TEXT'} DEFAULT ${column === 'license_status' ? "'inactive'" : column === 'is_active' ? 'FALSE' : column === 'uploaded_at' ? 'NOW()' : 'NULL'}`);
            }
        })().catch((error) => {
            licenseTableReady = null;
            throw error;
        });
    }
    await licenseTableReady;
}

async function getTenantLicenseStatus(tenantId) {
    await ensureLicenseTable();

    const licenseRes = await pool.query(
        'SELECT * FROM tenant_licenses WHERE tenant_id = $1 ORDER BY updated_at DESC LIMIT 1',
        [tenantId]
    );
    const license = licenseRes.rows[0];

    if (!license) {
        return {
            isValid: false,
            status: 'missing',
            reason: 'No license uploaded for this tenant yet.',
            license: null,
        };
    }

    if (!license.is_active || license.license_status !== 'active') {
        return {
            isValid: false,
            status: 'inactive',
            reason: 'This tenant license is currently inactive.',
            license,
        };
    }

    const validation = await validateLicenseDocument(license.license_key, tenantId);
    return { ...validation, license };
}

async function saveTenantLicense(tenantId, { licenseKey = null, fileName = null, notes = null } = {}) {
    await ensureLicenseTable();

    if (!licenseKey || typeof licenseKey !== 'string') {
        throw new Error('A signed license file is required.');
    }
    const validation = await validateLicenseDocument(licenseKey, tenantId);
    if (!validation.isValid) throw new Error(validation.reason);

    const now = new Date();
    const key = licenseKey.trim();
    const payload = {
        tenantId,
        licenseKey: key,
        fileName: fileName || null,
        notes: notes || null,
        validFrom: new Date(validation.payload.issued_at),
        validTo: new Date(validation.payload.expires_at),
        active: true,
        status: 'active',
        uploadedAt: now,
    };

    await pool.query(
        `INSERT INTO tenant_licenses (
            tenant_id, license_key, license_file_name, notes, valid_from, valid_to,
            license_status, is_active, uploaded_at, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
        ON CONFLICT (tenant_id)
        DO UPDATE SET
            license_key = EXCLUDED.license_key,
            license_file_name = EXCLUDED.license_file_name,
            notes = EXCLUDED.notes,
            valid_from = EXCLUDED.valid_from,
            valid_to = EXCLUDED.valid_to,
            license_status = EXCLUDED.license_status,
            is_active = EXCLUDED.is_active,
            uploaded_at = EXCLUDED.uploaded_at,
            updated_at = NOW()`,
        [
            payload.tenantId,
            payload.licenseKey,
            payload.fileName,
            payload.notes,
            payload.validFrom,
            payload.validTo,
            payload.status,
            payload.active,
            payload.uploadedAt,
        ]
    );

    return getTenantLicenseStatus(tenantId);
}

module.exports = {
    ensureLicenseTable,
    getTenantLicenseStatus,
    saveTenantLicense,
    validateLicenseDocument,
};
