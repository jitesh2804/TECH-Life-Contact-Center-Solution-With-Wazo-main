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
);

ALTER TABLE tenant_licenses
    ADD COLUMN IF NOT EXISTS license_key TEXT,
    ADD COLUMN IF NOT EXISTS license_file_name TEXT,
    ADD COLUMN IF NOT EXISTS license_status VARCHAR(32) DEFAULT 'inactive',
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS valid_to TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS notes TEXT;

CREATE INDEX IF NOT EXISTS idx_tenant_licenses_tenant_id ON tenant_licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_licenses_active ON tenant_licenses(is_active, valid_to);
