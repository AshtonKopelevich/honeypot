"""
generate_fs.py
--------------
Generates a randomized fake filesystem for Cowrie honeypot.
Simulates a realistic multi-user data centre server with interconnected
accounts, role-specific shell histories, and cross-referenced credentials.

Accounts created:
  - root       : superuser, sees everything
  - deploy     : deployment service account, owns app code
  - ubuntu     : default cloud VM user / sysadmin
  - admin      : senior sysadmin, security-focused
  - mysql      : system account (no login shell), DB config only
  - www-data   : system account (no login shell), web root only

Writes to:
  - /tmp/cowrie-src/                source tree for createfs
  - /home/cowrie/cowrie/honeyfs/    content layer for Cowrie runtime
"""

import random
import string
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import argparse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Randomization pools
# ---------------------------------------------------------------------------

HOSTNAMES = [
    "web-prod-01", "web-prod-02", "api-staging-01", "db-backup-03",
    "mail-relay-01", "dev-server-02", "build-agent-01", "monitor-01",
]

FIRST_NAMES = ["james", "sarah", "mike", "anna", "tom", "lisa", "chris", "emma"]
LAST_NAMES  = ["smith", "jones", "taylor", "brown", "wilson", "davies"]

REPO_NAMES = [
    "webapp", "api-service", "backend", "data-pipeline",
    "infra-scripts", "auth-service", "dashboard", "worker",
]

PACKAGES = [
    "flask", "django", "requests", "sqlalchemy", "celery", "redis",
    "boto3", "psycopg2-binary", "gunicorn", "pydantic", "fastapi",
    "uvicorn", "httpx", "python-dotenv", "alembic", "pytest",
]

DB_NAMES = [
    "production_db", "app_db", "users_db", "analytics_db", "main_db",
]

INTERNAL_IPS_TEMPLATES = [
    "192.168.1.{}", "192.168.0.{}", "10.0.0.{}", "10.10.1.{}"
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rnd_ip(template=None):
    t = template or random.choice(INTERNAL_IPS_TEMPLATES)
    return t.format(random.randint(2, 254))

def rnd_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choices(chars, k=length))

def rnd_hex(n=40):
    return ''.join(random.choices('0123456789abcdef', k=n))

def rnd_date(days_back=30):
    return datetime.now() - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59)
    )

def rnd_log_date():
    return rnd_date().strftime("%b %d %H:%M:%S")

def rnd_apache_date():
    return rnd_date().strftime("%d/%b/%Y:%H:%M:%S +0000")

def rnd_history(pool, n=20):
    return "\n".join(random.sample(pool, min(n, len(pool)))) + "\n"

def rnd_ssh_pubkey(user, host):
    key = rnd_hex(200)
    return f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{key} {user}@{host}\n"

def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def put(rel_path: str, content: str):
    write(SRC_DIR / rel_path, content)
    write(HONEYFS / rel_path, content)


# ---------------------------------------------------------------------------
# Shared state generator
# ---------------------------------------------------------------------------

def build_world():
    """Generate all shared state so cross-references are consistent."""
    template = random.choice(INTERNAL_IPS_TEMPLATES)

    world = {
        "hostname":    random.choice(HOSTNAMES),
        "repo":        random.choice(REPO_NAMES),
        "db_name":     random.choice(DB_NAMES),

        # Internal network — all accounts reference the same IPs
        "ip_db":       rnd_ip(template),
        "ip_backup":   rnd_ip(template),
        "ip_monitor":  rnd_ip(template),
        "ip_admin":    rnd_ip(template),
        "ip_deploy":   rnd_ip(template),

        # Credentials — shared across config files so they match
        "db_user":     "webapp_user",
        "db_pass":     rnd_password(14),
        "db_root_pass": rnd_password(16),
        "deploy_pass": rnd_password(12),
        "admin_pass":  rnd_password(12),

        # AWS-style keys (clearly fake format)
        "aws_key":     "AKIAIOSFODNN" + ''.join(
                           random.choices(string.ascii_uppercase + string.digits, k=8)),
        "aws_secret":  rnd_hex(20) + ''.join(
                           random.choices(string.ascii_letters + string.digits, k=20)),

        "secret_key":  rnd_hex(32),

        # People
        "admin_fn":    random.choice(FIRST_NAMES),
        "admin_ln":    random.choice(LAST_NAMES),
        "deploy_fn":   random.choice(FIRST_NAMES),
        "deploy_ln":   random.choice(LAST_NAMES),
    }

    world["admin_email"]  = f"{world['admin_fn']}.{world['admin_ln']}@company.internal"
    world["deploy_email"] = f"{world['deploy_fn']}.{world['deploy_ln']}@company.internal"

    return world


# ---------------------------------------------------------------------------
# /etc generators
# ---------------------------------------------------------------------------

def gen_passwd(w):
    deploy_uid = random.randint(1001, 1050)
    ubuntu_uid = deploy_uid + 1
    admin_uid  = ubuntu_uid + 1
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        f"mysql:x:111:114:MySQL Server,,,:/var/lib/mysql:/bin/false\n"
        f"deploy:x:{deploy_uid}:{deploy_uid}:Deploy Account,,,:/home/deploy:/bin/bash\n"
        f"ubuntu:x:{ubuntu_uid}:{ubuntu_uid}:Ubuntu User,,,:/home/ubuntu:/bin/bash\n"
        f"admin:x:{admin_uid}:{admin_uid}:System Administrator,,,:/home/admin:/bin/bash\n"
        "sshd:x:112:65534::/run/sshd:/usr/sbin/nologin\n"
    )


def gen_shadow(w):
    def fake_hash():
        return "$6$" + rnd_hex(16) + "$" + rnd_hex(86)
    return (
        f"root:{fake_hash()}:19500:0:99999:7:::\n"
        f"deploy:{fake_hash()}:19500:0:99999:7:::\n"
        f"ubuntu:{fake_hash()}:19500:0:99999:7:::\n"
        f"admin:{fake_hash()}:19500:0:99999:7:::\n"
        "daemon:*:19500:0:99999:7:::\n"
        "www-data:*:19500:0:99999:7:::\n"
        "mysql:*:19500:0:99999:7:::\n"
    )


def gen_hosts(w):
    return (
        f"127.0.0.1\tlocalhost\n"
        f"127.0.1.1\t{w['hostname']}\n"
        f"::1\tlocalhost ip6-localhost ip6-loopback\n"
        f"{w['ip_db']}\tdb-internal\n"
        f"{w['ip_backup']}\tbackup-server\n"
        f"{w['ip_monitor']}\tmonitoring\n"
        f"{w['ip_admin']}\tadmin-workstation\n"
        f"{w['ip_deploy']}\tdeploy-agent\n"
    )


def gen_sshd_config():
    return (
        "Port 22\n"
        "Protocol 2\n"
        "HostKey /etc/ssh/ssh_host_rsa_key\n"
        "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
        "HostKey /etc/ssh/ssh_host_ed25519_key\n"
        "UsePrivilegeSeparation yes\n"
        "KeyRegenerationInterval 3600\n"
        "ServerKeyBits 1024\n"
        "SyslogFacility AUTH\n"
        "LogLevel INFO\n"
        "LoginGraceTime 120\n"
        "PermitRootLogin yes\n"
        "StrictModes yes\n"
        "PubkeyAuthentication yes\n"
        "IgnoreRhosts yes\n"
        "HostbasedAuthentication no\n"
        "PermitEmptyPasswords no\n"
        "ChallengeResponseAuthentication no\n"
        "PasswordAuthentication yes\n"
        "X11Forwarding yes\n"
        "PrintMotd no\n"
        "AcceptEnv LANG LC_*\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n"
        "AllowUsers root deploy ubuntu admin\n"
    )


def gen_crontab(w):
    h = random.randint(1, 5)
    m = random.randint(0, 59)
    return (
        f"# /etc/crontab\n"
        f"SHELL=/bin/sh\n"
        f"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        f"{m} {h} * * * root /home/deploy/scripts/backup.sh >> /var/log/backup.log 2>&1\n"
        f"*/15 * * * * mysql /var/lib/mysql/scripts/db_health.sh\n"
        f"0 3 * * 0 root apt-get -y -q update && apt-get -y -q upgrade\n"
        f"*/5 * * * * root /usr/local/bin/check_services.sh\n"
    )


# ---------------------------------------------------------------------------
# /root generators
# ---------------------------------------------------------------------------

def gen_root_history(w):
    cmds = [
        "apt-get update",
        "apt-get upgrade -y",
        f"tail -f /var/log/auth.log",
        "ufw allow 80/tcp",
        "ufw allow 443/tcp",
        "ufw allow 22/tcp",
        "ufw status",
        f"cat /etc/shadow",
        f"cat /etc/passwd",
        "systemctl restart ssh",
        "systemctl status apache2",
        "netstat -tulpn",
        "ps aux",
        "ls /home",
        f"ls /home/deploy",
        f"ls /home/admin",
        "crontab -l",
        "nano /etc/ssh/sshd_config",
        "find / -perm -4000 2>/dev/null",
        "last",
        "who",
        "id",
        f"ssh ubuntu@{w['ip_monitor']}",
        f"cat /var/log/syslog | grep error",
        f"mysql -u root -p{w['db_root_pass']} -e 'SHOW DATABASES;'",
        "nano /etc/crontab",
        f"chown -R deploy:deploy /home/deploy/projects",
        f"passwd admin",
        "exit",
    ]
    return rnd_history(cmds, n=22)


def gen_root_notes(w):
    return (
        f"server: {w['hostname']}\n"
        f"-------------------------------\n"
        f"db server:        {w['ip_db']} (mysql root: {w['db_root_pass']})\n"
        f"backup server:    {w['ip_backup']}\n"
        f"monitoring:       {w['ip_monitor']}\n"
        f"admin workstation:{w['ip_admin']}\n\n"
        f"deploy user pass: {w['deploy_pass']}\n"
        f"admin user pass:  {w['admin_pass']}\n\n"
        f"TODO: disable root ssh login\n"
        f"TODO: rotate all passwords\n"
        f"TODO: fix mysql port exposed on {w['ip_db']}\n"
        f"TODO: move secrets out of .env files\n"
    )


def gen_root_passwords(w):
    return (
        f"# DO NOT SHARE - server credentials\n"
        f"mysql root:     {w['db_root_pass']}\n"
        f"mysql app user: {w['db_pass']}\n"
        f"deploy account: {w['deploy_pass']}\n"
        f"admin account:  {w['admin_pass']}\n"
        f"aws key id:     {w['aws_key']}\n"
        f"aws secret:     {w['aws_secret']}\n"
        f"ftp backup:     {rnd_password(10)}\n"
    )


# ---------------------------------------------------------------------------
# /home/deploy generators
# ---------------------------------------------------------------------------

def gen_deploy_history(w):
    cmds = [
        f"cd /home/deploy/projects/{w['repo']}",
        "git pull origin main",
        "git status",
        "git log --oneline -10",
        "git diff HEAD~1",
        "pip install -r requirements.txt",
        f"systemctl restart {w['repo']}",
        f"systemctl status {w['repo']}",
        "journalctl -u webapp -n 50",
        "sudo systemctl restart nginx",
        "sudo systemctl restart apache2",
        f"cat /home/deploy/projects/{w['repo']}/.env",
        "nano .env",
        "python3 manage.py migrate",
        "python3 manage.py collectstatic",
        f"scp backup.tar.gz ubuntu@{w['ip_backup']}:/backups/",
        f"ssh ubuntu@{w['ip_monitor']}",
        "docker ps",
        "docker-compose up -d",
        "docker-compose logs --tail=50",
        f"mysql -u {w['db_user']} -p{w['db_pass']} {w['db_name']}",
        "ls -la",
        "df -h",
        "free -m",
        "exit",
    ]
    return rnd_history(cmds, n=22)


def gen_deploy_env(w):
    return (
        f"# Application environment — {w['repo']}\n"
        f"APP_ENV=production\n"
        f"DEBUG=False\n\n"
        f"DB_HOST={w['ip_db']}\n"
        f"DB_PORT=3306\n"
        f"DB_NAME={w['db_name']}\n"
        f"DB_USER={w['db_user']}\n"
        f"DB_PASS={w['db_pass']}\n\n"
        f"SECRET_KEY={w['secret_key']}\n\n"
        f"AWS_ACCESS_KEY_ID={w['aws_key']}\n"
        f"AWS_SECRET_ACCESS_KEY={w['aws_secret']}\n"
        f"AWS_DEFAULT_REGION=us-east-1\n"
        f"S3_BUCKET=company-backups-prod\n\n"
        f"BACKUP_SERVER={w['ip_backup']}\n"
        f"MONITOR_HOST={w['ip_monitor']}\n"
    )


def gen_deploy_config_py(w):
    return (
        "import os\n\n"
        "class Config:\n"
        "    DEBUG = False\n"
        "    TESTING = False\n"
        "    SECRET_KEY = os.environ.get('SECRET_KEY')\n\n"
        "class ProductionConfig(Config):\n"
        "    DATABASE_URI = (\n"
        f"        f\"mysql://{{os.environ['DB_USER']}}:{{os.environ['DB_PASS']}}\"\n"
        f"        f\"@{{os.environ['DB_HOST']}}/{w['db_name']}\"\n"
        "    )\n"
    )


def gen_deploy_backup_sh(w):
    return (
        "#!/bin/bash\n"
        f"# Daily backup — {w['repo']}\n"
        f"set -e\n"
        f"DATE=$(date +%Y%m%d)\n"
        f"tar -czf /tmp/backup_$DATE.tar.gz /home/deploy/projects/{w['repo']}\n"
        f"mysqldump -u {w['db_user']} -p{w['db_pass']} {w['db_name']} > /tmp/db_$DATE.sql\n"
        f"scp /tmp/backup_$DATE.tar.gz ubuntu@{w['ip_backup']}:/backups/app/\n"
        f"scp /tmp/db_$DATE.sql ubuntu@{w['ip_backup']}:/backups/db/\n"
        f"rm /tmp/backup_$DATE.tar.gz /tmp/db_$DATE.sql\n"
        f"echo 'Backup complete' | mail -s 'Backup OK' {w['admin_email']}\n"
    )


def gen_deploy_requirements():
    chosen = random.sample(PACKAGES, k=random.randint(6, 10))
    lines = []
    for pkg in chosen:
        lines.append(f"{pkg}=={random.randint(0,3)}.{random.randint(0,12)}.{random.randint(0,5)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# /home/ubuntu generators
# ---------------------------------------------------------------------------

def gen_ubuntu_history(w):
    cmds = [
        "sudo apt-get update",
        "sudo apt-get upgrade -y",
        "sudo ufw status",
        f"sudo tail -f /var/log/auth.log",
        "df -h",
        "free -m",
        "top",
        "htop",
        "uptime",
        "last",
        "who",
        f"ssh root@{w['hostname']}",
        f"ssh admin@{w['ip_admin']}",
        f"ssh deploy@{w['ip_deploy']}",
        f"scp logs.tar.gz ubuntu@{w['ip_backup']}:/backups/logs/",
        "sudo systemctl status nginx",
        "sudo systemctl restart nginx",
        "sudo journalctl -xe",
        "sudo netstat -tulpn",
        "sudo ss -tlnp",
        "ps aux | grep python",
        "sudo adduser newuser",
        f"sudo usermod -aG sudo deploy",
        "sudo crontab -l",
        f"ping {w['ip_monitor']}",
        f"curl http://{w['ip_monitor']}:9090/metrics",
        "exit",
    ]
    return rnd_history(cmds, n=22)


def gen_ubuntu_notes(w):
    return (
        f"infrastructure notes\n"
        f"--------------------\n"
        f"hostname:    {w['hostname']}\n"
        f"db:          {w['ip_db']}:3306\n"
        f"backup:      {w['ip_backup']}\n"
        f"monitoring:  {w['ip_monitor']} (prometheus:9090, grafana:3000)\n"
        f"admin ws:    {w['ip_admin']}\n\n"
        f"contacts:\n"
        f"  admin:  {w['admin_email']}\n"
        f"  deploy: {w['deploy_email']}\n\n"
        f"notes:\n"
        f"  - deploy user owns /home/deploy/projects\n"
        f"  - mysql exposed on {w['ip_db']} — firewall rule pending\n"
        f"  - backup cron runs at 2am daily\n"
        f"  - grafana default creds not changed yet\n"
    )


# ---------------------------------------------------------------------------
# /home/admin generators
# ---------------------------------------------------------------------------

def gen_admin_history(w):
    cmds = [
        "sudo -l",
        "sudo su -",
        f"ssh root@{w['hostname']}",
        f"ssh ubuntu@{w['ip_monitor']}",
        f"ssh deploy@{w['ip_deploy']}",
        "sudo cat /etc/shadow",
        "sudo cat /etc/passwd",
        "sudo tail -f /var/log/auth.log",
        "sudo last",
        "sudo who",
        "sudo netstat -tulpn",
        "sudo ss -tlnp",
        "nmap -sV localhost",
        f"nmap -sV {w['ip_db']}",
        "sudo find / -perm -4000 2>/dev/null",
        "sudo find / -name '*.env' 2>/dev/null",
        "sudo find / -name 'passwords*' 2>/dev/null",
        f"sudo ufw deny from any to {w['ip_db']} port 3306",
        "sudo ufw status numbered",
        "sudo auditctl -l",
        "sudo grep 'Failed password' /var/log/auth.log | tail -20",
        "sudo grep 'Accepted' /var/log/auth.log | tail -20",
        f"curl -s http://{w['ip_monitor']}:9090/api/v1/alerts",
        "sudo iptables -L -n",
        f"mysql -h {w['ip_db']} -u root -p{w['db_root_pass']} -e 'SHOW PROCESSLIST;'",
        "history -c",
        "exit",
    ]
    return rnd_history(cmds, n=24)


def gen_admin_notes(w):
    return (
        f"security audit notes — {w['hostname']}\n"
        f"========================================\n\n"
        f"OPEN ISSUES:\n"
        f"  [HIGH]   MySQL port 3306 exposed on {w['ip_db']} — block externally\n"
        f"  [HIGH]   Root SSH login enabled — disable after deploy key setup\n"
        f"  [MEDIUM] Grafana default credentials on {w['ip_monitor']}:3000\n"
        f"  [MEDIUM] .env files contain plaintext AWS keys\n"
        f"  [LOW]    deploy user has no login timeout configured\n\n"
        f"CREDENTIALS (rotate quarterly):\n"
        f"  mysql root:  {w['db_root_pass']}\n"
        f"  mysql app:   {w['db_pass']}\n"
        f"  aws key:     {w['aws_key']}\n\n"
        f"CONTACTS:\n"
        f"  deploy: {w['deploy_email']}\n"
        f"  ubuntu: {w['admin_email']}\n\n"
        f"last audit: {rnd_date(days_back=14).strftime('%Y-%m-%d')}\n"
        f"next audit: {(datetime.now() + timedelta(days=random.randint(30,90))).strftime('%Y-%m-%d')}\n"
    )


def gen_admin_audit_sh(w):
    return (
        "#!/bin/bash\n"
        "# Quick security audit script\n"
        "echo '=== Failed logins (last 24h) ==='\n"
        "grep 'Failed password' /var/log/auth.log | grep \"$(date '+%b %d')\" | wc -l\n"
        "echo '=== Active sessions ==='\n"
        "who\n"
        "echo '=== Listening ports ==='\n"
        "ss -tlnp\n"
        "echo '=== SUID binaries ==='\n"
        "find / -perm -4000 2>/dev/null\n"
        f"echo '=== MySQL process list ==='\n"
        f"mysql -h {w['ip_db']} -u root -p{w['db_root_pass']} -e 'SHOW PROCESSLIST;' 2>/dev/null\n"
    )


# ---------------------------------------------------------------------------
# /var/lib/mysql generators (system account, no login)
# ---------------------------------------------------------------------------

def gen_mysql_config(w):
    return (
        "[mysqld]\n"
        f"user            = mysql\n"
        f"pid-file        = /var/run/mysqld/mysqld.pid\n"
        f"socket          = /var/run/mysqld/mysqld.sock\n"
        f"port            = 3306\n"
        f"basedir         = /usr\n"
        f"datadir         = /var/lib/mysql\n"
        f"tmpdir          = /tmp\n"
        f"bind-address    = 0.0.0.0\n"  # intentionally exposed — enticing
        f"max_connections = 150\n"
        f"log_error       = /var/log/mysql/error.log\n\n"
        f"[client]\n"
        f"user     = {w['db_user']}\n"
        f"password = {w['db_pass']}\n"
        f"host     = {w['ip_db']}\n"
    )


def gen_mysql_backup_sh(w):
    return (
        "#!/bin/bash\n"
        f"# MySQL backup script — runs as mysql user via cron\n"
        f"DATE=$(date +%Y%m%d_%H%M)\n"
        f"mysqldump -u root -p{w['db_root_pass']} --all-databases > /tmp/full_backup_$DATE.sql\n"
        f"gzip /tmp/full_backup_$DATE.sql\n"
        f"scp /tmp/full_backup_$DATE.sql.gz ubuntu@{w['ip_backup']}:/backups/mysql/\n"
        f"rm /tmp/full_backup_$DATE.sql.gz\n"
    )


# ---------------------------------------------------------------------------
# /var/www generators (www-data system account)
# ---------------------------------------------------------------------------

def gen_htaccess():
    return (
        "Options -Indexes\n"
        "ServerSignature Off\n\n"
        "<FilesMatch '\\.env$'>\n"
        "    Order allow,deny\n"
        "    Deny from all\n"
        "</FilesMatch>\n"
    )


def gen_web_config_php(w):
    return (
        "<?php\n"
        f"define('DB_HOST', '{w['ip_db']}');\n"
        f"define('DB_USER', '{w['db_user']}');\n"
        f"define('DB_PASS', '{w['db_pass']}');\n"
        f"define('DB_NAME', '{w['db_name']}');\n"
        f"define('SECRET_KEY', '{w['secret_key']}');\n"
        "?>\n"
    )


# ---------------------------------------------------------------------------
# Shared log generators
# ---------------------------------------------------------------------------

def gen_auth_log(w):
    users = ["root", "deploy", "ubuntu", "admin"]
    ips   = [w["ip_admin"], w["ip_deploy"], w["ip_monitor"]]
    lines = []
    for _ in range(random.randint(30, 50)):
        date = rnd_log_date()
        user = random.choice(users)
        ip   = random.choice(ips)
        port = random.randint(40000, 65000)
        if random.random() > 0.2:
            lines.append(
                f"{date} {w['hostname']} sshd[{random.randint(1000,9999)}]: "
                f"Accepted publickey for {user} from {ip} port {port} ssh2"
            )
        else:
            lines.append(
                f"{date} {w['hostname']} sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {ip} port {port} ssh2"
            )
    return "\n".join(sorted(lines)) + "\n"


def gen_syslog(w):
    services = ["kernel", "systemd", "cron", "NetworkManager", "mysqld", "nginx"]
    msgs = [
        "Started Session of user root.",
        "Reached target Multi-User System.",
        "Started Daily apt upgrade and clean activities.",
        "pam_unix(cron:session): session opened for user root",
        "Started Cleanup of Temporary Directories.",
        f"mysqld: ready for connections on port 3306",
        f"nginx: worker process {random.randint(1000,9999)} started",
    ]
    lines = []
    for _ in range(random.randint(40, 60)):
        date = rnd_log_date()
        svc  = random.choice(services)
        pid  = random.randint(100, 9999)
        lines.append(f"{date} {w['hostname']} {svc}[{pid}]: {random.choice(msgs)}")
    return "\n".join(sorted(lines)) + "\n"


def gen_apache_access_log(w):
    paths = ["/", "/index.html", "/login", "/api/v1/status",
             "/admin", "/wp-login.php", "/.env", "/robots.txt",
             "/api/v1/users", "/dashboard", "/static/app.js"]
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "curl/7.68.0",
        "python-requests/2.28.0",
    ]
    lines = []
    for _ in range(random.randint(40, 80)):
        ip     = random.choice([w["ip_admin"], w["ip_deploy"], w["ip_monitor"], rnd_ip()])
        date   = rnd_apache_date()
        path   = random.choice(paths)
        status = random.choice([200, 200, 200, 301, 404, 403])
        size   = random.randint(200, 8000)
        agent  = random.choice(agents)
        lines.append(f'{ip} - - [{date}] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"')
    return "\n".join(lines) + "\n"


def gen_apache_error_log(w):
    lines = []
    for _ in range(random.randint(5, 15)):
        date = rnd_date().strftime("%a %b %d %H:%M:%S.%f %Y")
        lines.append(
            f"[{date}] [error] [pid {random.randint(1000,9999)}] "
            f"[client {rnd_ip()}:80] File does not exist: /var/www/html/favicon.ico"
        )
    return "\n".join(lines) + "\n"


def gen_os_release():
    return (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\n'
        'ID_LIKE=debian\n'
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
        'VERSION_ID="22.04"\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        'VERSION_CODENAME=jammy\n'
    )


def gen_fake_rsa_key():
    body = rnd_hex(800)
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "\n".join(body[i:i+64] for i in range(0, len(body), 64))
        + "\n-----END RSA PRIVATE KEY-----\n"
    )


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def generate(SRC_DIR, HONEYFS):
    w = build_world()

    print(f"  Hostname   : {w['hostname']}")
    print(f"  Repo       : {w['repo']}")
    print(f"  DB name    : {w['db_name']}")
    print(f"  DB server  : {w['ip_db']}")
    print(f"  Backup     : {w['ip_backup']}")
    print(f"  Admin      : {w['admin_email']}")
    print(f"  Deploy     : {w['deploy_email']}")
    print()

    # ── /etc ──────────────────────────────────────────────────────────────
    put("etc/passwd",          gen_passwd(w))
    put("etc/shadow",          gen_shadow(w))
    put("etc/hostname",        w["hostname"] + "\n")
    put("etc/hosts",           gen_hosts(w))
    put("etc/os-release",      gen_os_release())
    put("etc/crontab",         gen_crontab(w))
    put("etc/ssh/sshd_config", gen_sshd_config())
    put("etc/mysql/my.cnf",    gen_mysql_config(w))

    # ── /root ─────────────────────────────────────────────────────────────
    put("root/.bash_history",       gen_root_history(w))
    put("root/.ssh/authorized_keys", rnd_ssh_pubkey(w["admin_fn"], "admin-workstation"))
    put("root/.ssh/id_rsa",         gen_fake_rsa_key())
    put("root/.ssh/known_hosts",
        f"{w['ip_backup']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n"
        f"{w['ip_monitor']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n")
    put("root/passwords.txt",       gen_root_passwords(w))
    put("root/notes.txt",           gen_root_notes(w))

    # ── /home/deploy ──────────────────────────────────────────────────────
    put("home/deploy/.bash_history",  gen_deploy_history(w))
    put("home/deploy/.ssh/authorized_keys",
        rnd_ssh_pubkey(w["deploy_fn"], "deploy-agent"))
    put("home/deploy/.ssh/known_hosts",
        f"{w['ip_backup']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n")
    put(f"home/deploy/projects/{w['repo']}/.env",         gen_deploy_env(w))
    put(f"home/deploy/projects/{w['repo']}/config.py",    gen_deploy_config_py(w))
    put(f"home/deploy/projects/{w['repo']}/requirements.txt", gen_deploy_requirements())
    put("home/deploy/scripts/backup.sh",                  gen_deploy_backup_sh(w))

    # ── /home/ubuntu ──────────────────────────────────────────────────────
    put("home/ubuntu/.bash_history",  gen_ubuntu_history(w))
    put("home/ubuntu/.ssh/authorized_keys",
        rnd_ssh_pubkey(w["admin_fn"], "admin-workstation"))
    put("home/ubuntu/.ssh/known_hosts",
        f"{w['ip_monitor']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n"
        f"{w['ip_backup']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n")
    put("home/ubuntu/notes.txt",      gen_ubuntu_notes(w))

    # ── /home/admin ───────────────────────────────────────────────────────
    put("home/admin/.bash_history",   gen_admin_history(w))
    put("home/admin/.ssh/authorized_keys",
        rnd_ssh_pubkey(w["admin_fn"], "admin-workstation"))
    put("home/admin/.ssh/id_rsa",     gen_fake_rsa_key())
    put("home/admin/.ssh/known_hosts",
        f"{w['hostname']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n"
        f"{w['ip_db']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n"
        f"{w['ip_backup']} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB{rnd_hex(64)}\n")
    put("home/admin/notes.txt",       gen_admin_notes(w))
    put("home/admin/audit.sh",        gen_admin_audit_sh(w))

    # ── /var/lib/mysql ────────────────────────────────────────────────────
    put("var/lib/mysql/scripts/db_health.sh", gen_mysql_backup_sh(w))

    # ── /var/www/html ─────────────────────────────────────────────────────
    put("var/www/html/.htaccess",    gen_htaccess())
    put("var/www/html/config.php",   gen_web_config_php(w))

    # ── /var/log ──────────────────────────────────────────────────────────
    put("var/log/auth.log",            gen_auth_log(w))
    put("var/log/syslog",              gen_syslog(w))
    put("var/log/apache2/access.log",  gen_apache_access_log(w))
    put("var/log/apache2/error.log",   gen_apache_error_log(w))

    # ── /tmp ──────────────────────────────────────────────────────────────
    put("tmp/.ICE-unix", "")

    print(f"  Written to : {SRC_DIR}")
    print(f"  Written to : {HONEYFS}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cowrie Filesystem Generator")
    parser.add_argument("--cowrie-dir",
        default=str(Path.home() / "cowrie"),
        help="Path to Cowrie installation (default: ~/cowrie)")
    args = parser.parse_args()

    SRC_DIR = Path("/tmp/cowrie-src")
    HONEYFS = Path(args.cowrie_dir) / "honeyfs"

    print("\nCowrie Filesystem Generator")
    print("=" * 40)

    if SRC_DIR.exists():
        shutil.rmtree(SRC_DIR)
    SRC_DIR.mkdir(parents=True)
    HONEYFS.mkdir(parents=True, exist_ok=True)

    generate(SRC_DIR, HONEYFS)
    print("\nDone. Run createfs next.\n")