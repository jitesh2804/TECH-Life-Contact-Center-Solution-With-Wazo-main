#!/usr/bin/env bash
set -Eeuo pipefail

# Install a local TECH-Life source folder into /opt/techlife.
# This script never clones or downloads application source from GitHub.

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export DEBIAN_FRONTEND=noninteractive

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-/opt/techlife}"
DB_NAME="${DB_NAME:-techlife}"
DB_USER="${DB_USER:-techlife}"
DB_PASS="${DB_PASS:-}"
APP_PORT="${APP_PORT:-3000}"
APP_TZ="${APP_TIMEZONE:-Asia/Kolkata}"
TECHLIFE_ADMIN_PASS="${TECHLIFE_ADMIN_PASS:-}"
INSTALL_WAZO="${INSTALL_WAZO:-no}"
WAZO_HOST="${WAZO_HOST:-127.0.0.1}"
WAZO_AUTH_USER="${WAZO_AUTH_USER:-techlife-collector}"
WAZO_AUTH_PASS="${WAZO_AUTH_PASS:-}"
SECRETS_FILE="/root/.techlife-local-install-secrets.env"
ADMIN_EXISTS=0

say() { printf '\n==> %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

need_root() {
  [[ "$EUID" -eq 0 ]] || die "Run as root: sudo bash $0"
}

find_source() {
  local candidate

  for candidate in "$SCRIPT_DIR" "$SCRIPT_DIR/techlife-node"; do
    if [[ -f "$candidate/package.json" ]] &&
       grep -Eq '"name"[[:space:]]*:[[:space:]]*"techlife-node"' "$candidate/package.json"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  die "Could not find techlife-node/package.json beside this installer."
}

validate_source() {
  local source="$1" item
  local required_files=(package.json app.js schema.sql seed.sql .env.example config/config.js)
  local required_dirs=(routes src views collector)
  local missing=()

  for item in "${required_files[@]}"; do
    [[ -f "$source/$item" ]] || missing+=("$item")
  done
  for item in "${required_dirs[@]}"; do
    [[ -d "$source/$item" ]] || missing+=("$item/")
  done

  if ((${#missing[@]})); then
    printf 'Local application folder is incomplete: %s\n' "$source" >&2
    printf 'Required content missing from the local folder:\n' >&2
    printf '  - %s\n' "${missing[@]}" >&2
    die "Restore the complete application folder locally, then rerun. No GitHub source will be fetched."
  fi
}

install_os_packages() {
  say "Installing Debian packages"
  apt-get update
  apt-get install -y ca-certificates curl openssl rsync nginx \
    postgresql postgresql-contrib postgresql-client python3
  systemctl enable --now postgresql nginx
}

check_node() {
  local major
  major=0
  if command -v node >/dev/null 2>&1; then
    major="$(node -p 'process.versions.node.split(".")[0]')"
  fi
  if [[ "$major" -lt 20 ]]; then
    say "Installing Node.js 22 from NodeSource (not GitHub)"
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
    major="$(node -p 'process.versions.node.split(".")[0]')"
  fi
  [[ "$major" -ge 20 ]] || die "Node.js 20+ is required; found $(node -v)."
  command -v npm >/dev/null 2>&1 || die "npm was not installed with Node.js."
}

load_secrets() {
  local supplied_db="$DB_PASS"
  local supplied_admin="$TECHLIFE_ADMIN_PASS"
  local supplied_session="${SESSION_SECRET:-}"
  local supplied_wazo_host="$WAZO_HOST"
  local supplied_wazo_user="$WAZO_AUTH_USER"
  local supplied_wazo_pass="$WAZO_AUTH_PASS"

  if [[ -f "$SECRETS_FILE" ]]; then
    # This file is root-owned and mode 600; values are shell-escaped below.
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"
  fi

  [[ -z "$supplied_db" ]] || DB_PASS="$supplied_db"
  [[ -z "$supplied_admin" ]] || TECHLIFE_ADMIN_PASS="$supplied_admin"
  [[ -z "$supplied_session" ]] || SESSION_SECRET="$supplied_session"
  [[ "$supplied_wazo_host" == "127.0.0.1" ]] || WAZO_HOST="$supplied_wazo_host"
  [[ "$supplied_wazo_user" == "techlife-collector" ]] || WAZO_AUTH_USER="$supplied_wazo_user"
  [[ -z "$supplied_wazo_pass" ]] || WAZO_AUTH_PASS="$supplied_wazo_pass"

  DB_PASS="${DB_PASS:-$(openssl rand -hex 24)}"
  TECHLIFE_ADMIN_PASS="${TECHLIFE_ADMIN_PASS:-$(openssl rand -hex 18)}"
  SESSION_SECRET="${SESSION_SECRET:-$(openssl rand -hex 32)}"

  umask 077
  {
    printf 'DB_PASS=%q\n' "$DB_PASS"
    printf 'TECHLIFE_ADMIN_PASS=%q\n' "$TECHLIFE_ADMIN_PASS"
    printf 'SESSION_SECRET=%q\n' "$SESSION_SECRET"
    printf 'WAZO_HOST=%q\n' "$WAZO_HOST"
    printf 'WAZO_AUTH_USER=%q\n' "$WAZO_AUTH_USER"
    printf 'WAZO_AUTH_PASS=%q\n' "$WAZO_AUTH_PASS"
  } > "$SECRETS_FILE"
  chmod 600 "$SECRETS_FILE"
}

setup_database() {
  say "Preparing PostgreSQL database"
  [[ -n "$DB_PASS" ]] || DB_PASS="$(openssl rand -hex 24)"

  [[ "$DB_NAME" =~ ^[A-Za-z0-9_]+$ ]] || die "DB_NAME may contain only letters, digits, and underscores."
  [[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || die "DB_USER may contain only letters, digits, and underscores."

  runuser -u postgres -- psql --set=db_user="$DB_USER" --set=db_pass="$DB_PASS" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'db_user', :'db_pass')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'db_user') \gexec
ALTER ROLE :"db_user" WITH LOGIN PASSWORD :'db_pass';
SQL

  local database_exists
  database_exists="$(runuser -u postgres -- psql -v db_name="$DB_NAME" -tA <<'SQL'
SELECT 1 FROM pg_database WHERE datname = :'db_name';
SQL
)"
  if [[ "$database_exists" != "1" ]]; then
    runuser -u postgres -- createdb -O "$DB_USER" "$DB_NAME"
  fi
}

deploy_source() {
  local source="$1"
  say "Copying local application source into $APP_DIR"

  mkdir -p "$APP_DIR"
  rsync -a \
    --exclude='.env' \
    --exclude='node_modules' \
    "$source/" "$APP_DIR/"

  cd "$APP_DIR"
  npm install --omit=dev
}

apply_database_files() {
  say "Applying available database schema files"
  export PGPASSWORD="$DB_PASS"
  local schemas=(
    schema.sql
    robo_agent_schema.sql
    webrtc_schema.sql
    mask_settings_schema.sql
    crm_integration_schema.sql
    tenant_hierarchy_schema.sql
    features_batch2_schema.sql
    ivr_management_schema.sql
    tenant_license_schema.sql
  )
  local schema

  for schema in "${schemas[@]}"; do
    if [[ -f "$APP_DIR/$schema" ]]; then
      echo "Applying $schema"
      psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$DB_USER" \
        -d "$DB_NAME" -f "$APP_DIR/$schema"
    fi
  done

  if [[ -f "$APP_DIR/fix_permissions.sql" ]]; then
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 \
      -d "$DB_NAME" -f "$APP_DIR/fix_permissions.sql"
  fi
}

seed_initial_admin() {
  say "Seeding the initial admin only when no admin account exists"
  cd "$APP_DIR"
  export PGPASSWORD="$DB_PASS"

  local existing
  existing="$(psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -tAc \
    "SELECT count(*) FROM users WHERE username='admin';")"
  if [[ "$existing" != "0" ]]; then
    ADMIN_EXISTS=1
    say "Admin already exists; leaving users unchanged"
    return
  fi

  local hash temp_seed
  hash="$(node -e "console.log(require('bcryptjs').hashSync(process.argv[1],10))" \
    "$TECHLIFE_ADMIN_PASS")"
  temp_seed="$(mktemp)"
  trap 'rm -f "$temp_seed"' RETURN
  cp "$APP_DIR/seed.sql" "$temp_seed"

  python3 - "$temp_seed" "$hash" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
content, count = re.subn(
    r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}",
    sys.argv[2],
    path.read_text(),
    count=1,
)
if count != 1:
    raise SystemExit("Could not locate the bcrypt password hash in seed.sql")
path.write_text(content)
PY

  psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$DB_USER" \
    -d "$DB_NAME" -f "$temp_seed"
  rm -f "$temp_seed"
  trap - RETURN
}

write_environment() {
  say "Writing application environment"
  cat > "$APP_DIR/.env" <<EOF
APP_PORT=$APP_PORT
SESSION_SECRET=$SESSION_SECRET
APP_TIMEZONE=$APP_TZ
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
WAZO_HOST=$WAZO_HOST
WAZO_WS_URL=wss://${WAZO_HOST}/api/websocketd/
WAZO_CALLD_URL=https://${WAZO_HOST}:9500/1.0
WAZO_CONFD_URL=https://${WAZO_HOST}:9486/1.1
WAZO_AGENTD_URL=https://${WAZO_HOST}:9493/1.0
WAZO_CHATD_URL=https://${WAZO_HOST}:9304/1.0
WAZO_AUTH_URL=https://${WAZO_HOST}:9497/0.1
WAZO_AUTH_USER=$WAZO_AUTH_USER
WAZO_AUTH_PASS=$WAZO_AUTH_PASS
WAZO_TLS_REJECT_UNAUTHORIZED=false
EOF
  chmod 600 "$APP_DIR/.env"
}

create_services() {
  say "Creating TECH-Life systemd service"
  if ! id techlife >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin techlife
  fi
  chown -R techlife:techlife "$APP_DIR"

  cat > /etc/systemd/system/techlife-web.service <<EOF
[Unit]
Description=TECH-Life Contact Center Web
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$(command -v npm) start
Restart=always
RestartSec=5
User=techlife
Group=techlife

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now techlife-web
}

configure_nginx() {
  local host="${DOMAIN:-$(hostname -I | awk '{print $1}')}"
  [[ -n "$host" ]] || host=localhost

  cat > /etc/nginx/sites-available/techlife <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $host;
    client_max_body_size 100m;
    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
  ln -sfn /etc/nginx/sites-available/techlife /etc/nginx/sites-enabled/techlife
  nginx -t
  systemctl reload nginx
}

main() {
  need_root
  source /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "12" ]] ||
    die "Debian 12 is required; detected ${PRETTY_NAME:-unknown}."
  [[ "${INSTALL_WAZO}" == "no" ]] ||
    die "This local installer does not install Wazo or fetch Ansible files. Install Wazo separately from local media first."

  local source
  source="$(find_source)"
  validate_source "$source"
  load_secrets
  install_os_packages
  check_node
  setup_database
  deploy_source "$source"
  apply_database_files
  seed_initial_admin
  write_environment
  create_services
  configure_nginx

  local app_host="${DOMAIN:-$(hostname -I | awk '{print $1}')}"
  [[ -n "$app_host" ]] || app_host=localhost
  if [[ "$ADMIN_EXISTS" -eq 0 ]]; then
    cat > /root/techlife-install-credentials.txt <<EOF
TECH-Life URL: http://${app_host}/login
Tenant: acme
Username: admin
Password: $TECHLIFE_ADMIN_PASS

Database: $DB_NAME
Database user: $DB_USER
Database password: $DB_PASS
EOF
    chmod 600 /root/techlife-install-credentials.txt
  else
    cat > /root/techlife-install-credentials.txt <<EOF
TECH-Life URL: http://${app_host}/login
Tenant: acme
Username: admin
Existing admin password was not changed by this installation.

Database: $DB_NAME
Database user: $DB_USER
Database password: $DB_PASS
EOF
    chmod 600 /root/techlife-install-credentials.txt
  fi
  say "Installation completed. Credentials saved to /root/techlife-install-credentials.txt"
}

main "$@"
