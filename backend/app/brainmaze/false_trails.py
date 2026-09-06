"""False Trail Generator — creates fake digital trails that lead attackers in circles.

All fake data is designed to be believable but lead nowhere (or to honeypots).
Generated trails are stored in Neo4j as :FalseTrail nodes linked to attacker sessions.

Trails include:
- Fake DNS records pointing to honeypot IPs
- Fake credentials with canary tokens
- Fake bash_history entries
- Fake config files (.env, config.yml, docker-compose.yml)
- Fake /etc/passwd entries
"""

from __future__ import annotations

import json
import logging
import random
import secrets
import string
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)
random.seed(secrets.randbelow(2**32))

# Honeypot IP range — these are RFC 5737 documentation IPs, safe to "point to"
HONEYPOT_IPS = [
    "192.0.2.10", "192.0.2.23", "192.0.2.47", "192.0.2.88",
    "198.51.100.12", "198.51.100.34", "198.51.100.56", "198.51.100.77",
    "203.0.113.5", "203.0.113.21", "203.0.113.44", "203.0.113.99",
]

# Realistic-looking but fake domains
FAKE_DOMAINS = [
    "internal.corp.local", "staging.lab.local", "dev.internal.local",
    "ops-grid.corp.local", "data-svc.internal.local", "auth-svc.corp.local",
    "monitor.lab.local", "ci-jenkins.internal.local", "vault.corp.local",
    "k8s-prod.corp.local", "redis-cluster.internal.local", "mq-staging.lab.local",
]

# Realistic usernames
FAKE_USERNAMES = [
    "jwilson", "schen", "mtorres", "dkumar", "aswift", "rjones", "kpatel",
    "bnguyen", "lsantos", "tobrien", "jmiller", "ngupta", "crivera",
    "eblack", "hsato", "ryang", "mrossi", "dcohen", "vkovalenko", "fali",
    "svc_backup", "svc_monitor", "svc_deploy", "svc_health", "svc_report",
    "jenkins", "gitlab-runner", "ansible", "prometheus", "grafana",
]

# Realistic password patterns (fake but look real)
PASSWORD_TEMPLATES = [
    "Summer2024!#{n}", "Winter2023#{n}@", "P@ssw0rd#{n}!", "S3cure#{n}Pass!",
    "Chang3M3#{n}#", "C0rp#{n}!Access", "D3vOps#{n}#{c}", "Pr0d#{n}K3y!",
    "MyP@ss#{n}word", "S3cr3t#{n}S@uce", "Adm1n#{n}!23", "L3tm3in#{n}#",
]


# ═══════════════════════════════════════════════════════════════════════
#  FALSE TRAIL GENERATOR
# ═══════════════════════════════════════════════════════════════════════

class FalseTrailGenerator:
    """Generates fake digital trails that lead attackers in circles.

    All generated trails are stored in Neo4j as :FalseTrail nodes.
    """

    def __init__(self) -> None:
        self._trails: list[dict[str, Any]] = []

    # ── FAKE DNS RECORDS ────────────────────────────────────────────

    def generate_fake_dns(self, domain: str) -> dict[str, Any]:
        """Generate fake DNS records pointing to honeypot IPs.

        Returns A, CNAME, MX, TXT records that look real but point to
        documentation/honeypot IP ranges.
        """
        subdomains = [
            "mail", "vpn", "remote", "internal", "staging", "dev",
            "api", "admin", "portal", "jenkins", "gitlab", "jira",
            "grafana", "prometheus", "kibana", "vault", "consul",
            "redis", "elastic", "rabbitmq", "nomad", "traefik",
        ]

        records = []
        for sub in random.sample(subdomains, k=min(8, len(subdomains))):
            ip = random.choice(HONEYPOT_IPS)
            records.append({
                "hostname": f"{sub}.{domain}",
                "type": "A",
                "value": ip,
                "ttl": random.choice([300, 600, 3600, 86400]),
            })

        # Add some CNAMEs
        for sub in random.sample(subdomains, k=3):
            target = random.choice(FAKE_DOMAINS)
            records.append({
                "hostname": f"{sub}.{domain}",
                "type": "CNAME",
                "value": target,
                "ttl": 3600,
            })

        # Add MX records
        records.append({
            "hostname": domain,
            "type": "MX",
            "value": f"10 mail.{domain}",
            "ttl": 3600,
        })

        # Add TXT records (SPF, DKIM-like)
        records.append({
            "hostname": domain,
            "type": "TXT",
            "value": '"v=spf1 ip4:192.0.2.0/24 include:_spf.{domain} ~all"',
            "ttl": 3600,
        })
        records.append({
            "hostname": f"_dmarc.{domain}",
            "type": "TXT",
            "value": '"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"',
            "ttl": 3600,
        })

        trail = {
            "trail_id": f"ft_dns_{int(datetime.now(timezone.utc).timestamp())}",
            "trail_type": "dns",
            "domain": domain,
            "records": records,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_trail(trail)
        logger.info("BRAINMAZE: Generated %d fake DNS records for %s", len(records), domain)
        return trail

    # ── FAKE CREDENTIALS ────────────────────────────────────────────

    def generate_fake_credentials(self, count: int = 10) -> dict[str, Any]:
        """Generate fake but realistic-looking credentials.

        Includes user:pass pairs, API keys, and AWS keys with canary tokens.
        """
        credentials = []

        for _ in range(count):
            cred_type = random.choice(["userpass", "api_key", "aws_key", "ssh_key", "token"])

            if cred_type == "userpass":
                username = random.choice(FAKE_USERNAMES)
                password = self._gen_password()
                credentials.append({
                    "type": "userpass",
                    "username": username,
                    "password": password,
                    "source": random.choice([
                        "/etc/shadow",
                        "config/database.yml",
                        ".env.production",
                        "backup/credentials.txt",
                        "ldap://dc01.corp.local",
                    ]),
                })

            elif cred_type == "api_key":
                credentials.append({
                    "type": "api_key",
                    "service": random.choice(["stripe", "sendgrid", "slack", "twilio", "github", "aws", "gcp"]),
                    "key": self._gen_api_key(),
                    "source": random.choice([
                        ".env",
                        "config/secrets.yml",
                        "~/.config/api-keys.json",
                        "jenkins/credentials.xml",
                    ]),
                })

            elif cred_type == "aws_key":
                credentials.append({
                    "type": "aws_key",
                    "access_key_id": self._gen_aws_access_key(),
                    "secret_access_key": self._gen_aws_secret(),
                    "region": random.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]),
                    "source": random.choice([
                        "~/.aws/credentials",
                        ".env.production",
                        "terraform/.tfvars",
                        "jenkins/aws-config.json",
                    ]),
                })

            elif cred_type == "ssh_key":
                credentials.append({
                    "type": "ssh_key",
                    "user": random.choice(FAKE_USERNAMES),
                    "key_type": random.choice(["rsa", "ed25519", "ecdsa"]),
                    "fingerprint": self._gen_ssh_fingerprint(),
                    "source": f"~/.ssh/authorized_keys ({random.choice(FAKE_USERNAMES)})",
                })

            elif cred_type == "token":
                credentials.append({
                    "type": "token",
                    "service": random.choice(["jwt", "oauth", "personal_access", "service_account"]),
                    "token": self._gen_token(),
                    "source": random.choice([
                        "Authorization header (captured)",
                        "cookie jar",
                        "browser session storage",
                        "api gateway logs",
                    ]),
                })

        trail = {
            "trail_id": f"ft_cred_{int(datetime.now(timezone.utc).timestamp())}",
            "trail_type": "credentials",
            "credentials": credentials,
            "count": len(credentials),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_trail(trail)
        logger.info("BRAINMAZE: Generated %d fake credentials", len(credentials))
        return trail

    # ── FAKE BASH HISTORY ────────────────────────────────────────────

    def generate_fake_history(self) -> dict[str, Any]:
        """Generate fake bash_history entries that look real."""
        history_entries = [
            "ssh -i ~/.ssh/id_rsa deploy@10.0.2.20",
            "ssh -i ~/.ssh/prod_key root@10.0.2.15",
            "mysql -u root -pS3cureP@ss! -h 10.0.2.15 production",
            "sudo su -",
            "cat /etc/shadow | grep root",
            "curl -s http://10.0.2.30:8080/health",
            "kubectl get pods -n production",
            "kubectl get secrets -n production",
            "docker exec -it web-prod-02 bash",
            "psql -U admin -d production -h 10.0.2.15",
            "redis-cli -h 10.0.2.25 -a r3d1sS3cr3t",
            "mongosh mongodb://admin:m0ng0P@ss@10.0.2.35:27017/admin",
            "scp backup.tar.gz deploy@10.0.2.20:/backups/",
            "rsync -avz /var/www/ deploy@10.0.2.20:/var/www/",
            "aws s3 ls s3://company-backups-2024/",
            "aws s3 sync s3://company-secrets/ ./secrets/",
            "terraform apply -auto-approve",
            "ansible-playbook -i production deploy.yml -e @secrets.yml",
            "vault kv get secret/production/db-credentials",
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "git clone https://admin:g1tHub_T0k3n@github.com/company/internal-tools.git",
            "npm run db:migrate:prod",
            "python manage.py migrate --settings=production_settings",
            "cat .env.production",
            "vi /etc/nginx/sites-enabled/default",
            "systemctl restart nginx",
            "journalctl -u nginx -f",
            "tail -f /var/log/auth.log",
            "grep 'Failed password' /var/log/auth.log | tail -20",
            "cat /etc/hosts",
            "ifconfig | grep inet",
            "netstat -tulpn",
            "crontab -e",
            "find / -name '*.pem' 2>/dev/null",
            "find / -name 'id_rsa' 2>/dev/null",
            "find / -name '.env' 2>/dev/null",
            "wget http://10.0.2.40/install.sh -O /tmp/install.sh",
            "chmod +x /tmp/install.sh && /tmp/install.sh",
            "curl -sSL https://get.docker.com/ | sh",
            "docker login -u admin -p D0ck3rH4ub! registry.corp.local",
            "cat /proc/cpuinfo | head -5",
            "free -h",
            "df -h",
            "du -sh /var/log/*",
            "tar czf /tmp/configs.tar.gz /etc/",
            "nc -zv 10.0.2.15 5432",
            "telnet 10.0.2.30 8080",
            "nmap -sV 10.0.2.0/24",
            "sudo nmap -sS -O 10.0.2.0/24",
        ]

        # Select a realistic subset and add line numbers
        selected = random.sample(history_entries, k=min(30, len(history_entries)))
        numbered = [f"{i+1}  {entry}" for i, entry in enumerate(selected)]

        trail = {
            "trail_id": f"ft_hist_{int(datetime.now(timezone.utc).timestamp())}",
            "trail_type": "history",
            "user": random.choice(FAKE_USERNAMES),
            "entries": numbered,
            "count": len(numbered),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_trail(trail)
        logger.info("BRAINMAZE: Generated %d fake bash_history entries", len(numbered))
        return trail

    # ── FAKE CONFIG FILES ───────────────────────────────────────────

    def generate_fake_config(self, filename: str) -> dict[str, Any]:
        """Generate fake config files with canary tokens.

        Supports: .env, config.yml, docker-compose.yml
        """
        filename_lower = filename.lower()

        if ".env" in filename_lower:
            content = self._gen_env_config()
        elif "config.yml" in filename_lower or "config.yaml" in filename_lower:
            content = self._gen_yaml_config()
        elif "docker-compose" in filename_lower:
            content = self._gen_docker_compose()
        elif "nginx" in filename_lower:
            content = self._gen_nginx_config()
        elif "sshd_config" in filename_lower:
            content = self._gen_sshd_config()
        else:
            content = self._gen_env_config()

        trail = {
            "trail_id": f"ft_cfg_{int(datetime.now(timezone.utc).timestamp())}",
            "trail_type": "config",
            "filename": filename,
            "content": content,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_trail(trail)
        logger.info("BRAINMAZE: Generated fake config file: %s", filename)
        return trail

    # ── FAKE USERS ───────────────────────────────────────────────────

    def generate_fake_users(self) -> dict[str, Any]:
        """Generate fake /etc/passwd entries with realistic usernames."""
        shells = ["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/sbin/nologin", "/bin/false"]
        users = []

        # System-ish users
        for name in ["deploy", "jenkins", "gitlab", "runner", "consul", "vault", "nomad"]:
            uid = random.randint(900, 999)
            users.append({
                "username": name,
                "uid": uid,
                "gid": uid,
                "home": f"/var/lib/{name}",
                "shell": "/usr/sbin/nologin",
                "gecos": f"{name} service account,,,",
            })

        # Regular users
        for name in random.sample(FAKE_USERNAMES, k=min(15, len(FAKE_USERNAMES))):
            uid = random.randint(1000, 5000)
            users.append({
                "username": name,
                "uid": uid,
                "gid": 100,  # users group
                "home": f"/home/{name}",
                "shell": random.choice(shells),
                "gecos": f"{name.replace('.', ' ').title()},,,",
            })

        # Format as /etc/passwd lines
        passwd_lines = [
            f"{u['username']}:x:{u['uid']}:{u['gid']}:{u['gecos']}:{u['home']}:{u['shell']}"
            for u in users
        ]

        trail = {
            "trail_id": f"ft_users_{int(datetime.now(timezone.utc).timestamp())}",
            "trail_type": "users",
            "entries": passwd_lines,
            "users": users,
            "count": len(users),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_trail(trail)
        logger.info("BRAINMAZE: Generated %d fake /etc/passwd entries", len(users))
        return trail

    # ── TRAIL STORAGE ────────────────────────────────────────────────

    def get_all_trails(self) -> list[dict[str, Any]]:
        """Get all generated false trails."""
        return list(self._trails)

    def get_trails_by_type(self, trail_type: str) -> list[dict[str, Any]]:
        """Get trails filtered by type."""
        return [t for t in self._trails if t.get("trail_type") == trail_type]

    def _store_trail(self, trail: dict[str, Any]) -> None:
        """Store trail in memory and Neo4j."""
        self._trails.append(trail)
        if len(self._trails) > 1000:
            self._trails = self._trails[-1000:]

        # Store in Neo4j
        try:
            cypher_write(
                """
                CREATE (f:FalseTrail {
                    trail_id: $trail_id,
                    trail_type: $trail_type,
                    generated_at: $generated_at,
                    data: $data
                })
                """,
                {
                    "trail_id": trail["trail_id"],
                    "trail_type": trail["trail_type"],
                    "generated_at": trail["generated_at"],
                    "data": json.dumps(trail, default=str),
                },
            )
        except Exception as e:
            logger.debug("BRAINMAZE: Neo4j trail storage failed (non-critical): %s", e)

    # ── HELPER GENERATORS ────────────────────────────────────────────

    def _gen_password(self) -> str:
        n = random.randint(1, 999)
        template = random.choice(PASSWORD_TEMPLATES)
        return template.format(n=n, c=random.choice(["!", "#", "@", "$"]))

    def _gen_api_key(self) -> str:
        prefix = random.choice(["sk-proj-", "sk_live_", "SG.", "xoxb-", "SK", "ghp_", "gho_"])
        body = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(24, 48)))
        return f"{prefix}{body}"

    def _gen_aws_access_key(self) -> str:
        return "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))

    def _gen_aws_secret(self) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits + "/+=", k=40))

    def _gen_ssh_fingerprint(self) -> str:
        parts = ["".join(random.choices("0123456789abcdef", k=2)) for _ in range(20)]
        return "SHA256:" + ":".join(parts)

    def _gen_token(self) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits + "-_.~", k=random.randint(32, 64)))

    def _gen_env_config(self) -> str:
        lines = [
            "# Production Environment Configuration",
            "# DO NOT COMMIT TO VERSION CONTROL",
            "",
            "APP_ENV=production",
            "APP_DEBUG=false",
            "APP_PORT=8080",
            "",
            "DATABASE_URL=postgresql://admin:S3cureP@ss!@10.0.2.15:5432/production",
            "DATABASE_POOL_SIZE=20",
            "DATABASE_TIMEOUT=30000",
            "",
            "REDIS_URL=redis://10.0.2.25:6379/0",
            "REDIS_PASSWORD=r3d1sS3cr3t",
            "",
            "JWT_SECRET=e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4",
            "JWT_EXPIRY=3600",
            "",
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS_REGION=us-east-1",
            "AWS_S3_BUCKET=company-production-assets",
            "",
            "STRIPE_SECRET=sk_live_9f8e7d6c5b4a3f2e",
            "SENDGRID_KEY=SG.abc123def456.ghi789jkl012mno345pqr678stu901",
            "SLACK_TOKEN=xoxb-123456789-123456789-a1b2c3d4e5f6",
            "",
            "SMTP_HOST=mail.corp.local",
            "SMTP_PORT=587",
            "SMTP_USER=notifications@corp.local",
            "SMTP_PASS=N0t1f1c@t10ns!",
            "",
            "VAULT_ADDR=https://vault.corp.local:8200",
            "VAULT_TOKEN=s.abcdef1234567890ghijkl",
            "",
            "KUBECONFIG=/home/deploy/.kube/config-prod",
            "K8S_CLUSTER=production-cluster",
            "",
            "# Canary token: a7b3c9d2e1f0 — if this appears in logs, someone read this file",
            "CANARY_TOKEN=a7b3c9d2e1f0",
        ]
        return "\n".join(lines)

    def _gen_yaml_config(self) -> str:
        return f"""# Application Configuration — Production
# Last updated: 2024-08-15 by Dave Mitchell
# WARNING: Contains sensitive information — do not share

app:
  name: production-api
  version: 2.4.1
  environment: production
  port: 8080
  workers: 8

database:
  host: 10.0.2.15
  port: 5432
  name: production
  user: admin
  password: S3cureP@ss!
  pool_size: 20
  timeout: 30000
  ssl: true

redis:
  host: 10.0.2.25
  port: 6379
  password: r3d1sS3cr3t
  db: 0

cache:
  driver: redis
  ttl: 3600
  prefix: "prod:"

queue:
  driver: rabbitmq
  host: 10.0.2.35
  port: 5672
  user: queue_admin
  password: R4bb1tMQ!S3cure
  vhost: /production

storage:
  driver: s3
  bucket: company-production-assets
  region: us-east-1
  access_key: AKIAIOSFODNN7EXAMPLE
  secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

monitoring:
  enabled: true
  sentry_dsn: https://abc123def456@sentry.corp.local/1
  prometheus: http://10.0.2.40:9090
  grafana: http://10.0.2.41:3000

secrets:
  jwt: e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4
  api_key: sk-proj-abc123def456ghi789jkl012mno345pqr678
  # Canary: f0e1d2c3b4a5 — triggers alert if exfiltrated
  canary: f0e1d2c3b4a5
"""

    def _gen_docker_compose(self) -> str:
        return """version: '3.8'

services:
  api:
    image: registry.corp.local/production-api:2.4.1
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://admin:S3cureP@ss!@10.0.2.15:5432/production
      - REDIS_URL=redis://10.0.2.25:6379/0
      - JWT_SECRET=e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4
    depends_on:
      - postgres
      - redis
    deploy:
      replicas: 4
      resources:
        limits:
          memory: 2G
    networks:
      - production

  postgres:
    image: postgres:15.4
    environment:
      - POSTGRES_USER=admin
      - POSTGRES_PASSWORD=S3cureP@ss!
      - POSTGRES_DB=production
    volumes:
      - pg_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - production

  redis:
    image: redis:7.2.3
    command: redis-server --requirepass r3d1sS3cr3t
    ports:
      - "6379:6379"
    networks:
      - production

  nginx:
    image: nginx:1.25.3
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - api
    networks:
      - production

  rabbitmq:
    image: rabbitmq:3.12.11-management
    environment:
      - RABBITMQ_DEFAULT_USER=queue_admin
      - RABBITMQ_DEFAULT_PASS=R4bb1tMQ!S3cure
    ports:
      - "5672:5672"
      - "15672:15672"
    networks:
      - production

volumes:
  pg_data:

networks:
  production:
    driver: bridge
"""

    def _gen_nginx_config(self) -> str:
        return """server {
    listen 80;
    server_name api.corp.local;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.corp.local;

    ssl_certificate /etc/nginx/certs/api.corp.local.crt;
    ssl_certificate_key /etc/nginx/certs/api.corp.local.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://10.0.2.20:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/v1/ {
        proxy_pass http://10.0.2.20:8080;
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    location /admin {
        proxy_pass http://10.0.2.30:8081;
        allow 10.0.0.0/8;
        deny all;
    }

    location /health {
        proxy_pass http://10.0.2.20:8080/health;
        access_log off;
    }
}
"""

    def _gen_sshd_config(self) -> str:
        return """# /etc/ssh/sshd_config — Production Configuration
# Last modified: 2024-07-10

Port 22
Port 2222
AddressFamily inet
ListenAddress 0.0.0.0

PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes

AuthorizedKeysFile .ssh/authorized_keys
AuthorizedKeysFile /etc/ssh/authorized_keys/%u

X11Forwarding no
AllowTcpForwarding yes
PermitTunnel yes
ClientAliveInterval 300
ClientAliveCountMax 3

UsePAM yes
AllowUsers deploy admin jenkins svc_backup
DenyUsers guest nobody

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server

# Canary: ssh -p 2222 admin@10.0.2.15 triggers alert
"""


# ── Singleton ────────────────────────────────────────────────────────────

_generator: Optional[FalseTrailGenerator] = None


def get_false_trail_generator() -> FalseTrailGenerator:
    global _generator
    if _generator is None:
        _generator = FalseTrailGenerator()
    return _generator