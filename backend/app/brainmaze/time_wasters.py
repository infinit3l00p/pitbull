"""Time Wasters — generates decoy content that wastes attacker time.

All content is designed to be interesting enough to investigate but ultimately useless.
Tracks time wasted per attacker in Neo4j.

Generates:
- Fake SQL database dumps with realistic-looking data
- Fake filesystem listings with interesting filenames
- Fake API documentation with endpoints that don't exist
- Fake source code with fake vulnerabilities
- Fake git repositories with fake commit history
"""

from __future__ import annotations

import json
import logging
import random
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.database import cypher_write

logger = logging.getLogger(__name__)
random.seed(secrets.randbelow(2**32))

# ═══════════════════════════════════════════════════════════════════════
#  DATA TEMPLATES
# ═══════════════════════════════════════════════════════════════════════

FAKE_FIRST_NAMES = [
    "James", "Sarah", "Michael", "Emily", "David", "Jessica", "Robert", "Ashley",
    "Daniel", "Amanda", "Kevin", "Melissa", "Brian", "Stephanie", "Jason", "Nicole",
    "Ryan", "Elizabeth", "Eric", "Jennifer", "Andrew", "Lisa", "Tyler", "Rachel",
]

FAKE_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
]

FAKE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "company.com", "corp.local",
    "protonmail.com", "hotmail.com", "icloud.com",
]

FAKE_TABLE_NAMES = [
    "users", "orders", "products", "payments", "subscriptions", "api_keys",
    "sessions", "audit_logs", "customer_data", "credit_cards", "employees",
    "departments", "transactions", "webhooks", "integrations", "notifications",
]

FAKE_FILENAMES = [
    "backup_2024_q3.sql", "credentials.txt", "api_keys.json", ".env.production",
    "customer_data.csv", "password_reset_tokens.db", "payment_logs.json",
    "ssl_keys/", "private_key.pem", "cert.pem", "ca-bundle.crt",
    "nginx.conf", "docker-compose.yml", "Dockerfile", ".gitignore",
    "terraform.tfstate", "secrets.tfvars", "variables.tf",
    "jenkins_credentials.xml", "ansible_vault.yml", "vault_keys.json",
    "k8s_secrets.yaml", "configmap.yaml", "deployment.yaml",
    "id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
    "shadow", "passwd", "group", "sudoers",
    "access.log", "error.log", "auth.log", "secure",
    "application.properties", "settings.py", "config.js", "database.yml",
    "schema.sql", "migrations/", "seeds.sql", "init.sql",
    "README.md", "CHANGELOG.md", "LICENSE", "CONTRIBUTING.md",
    "debug.log", "error_trace.txt", "heap_dump.bin", "thread_dump.txt",
    "network_capture.pcap", "traffic_analysis.json", "vuln_scan.xml",
]


# ═══════════════════════════════════════════════════════════════════════
#  TIME WASTER GENERATOR
# ═══════════════════════════════════════════════════════════════════════

class TimeWasterGenerator:
    """Generates decoy content that wastes attacker time.

    All content is designed to be interesting enough to investigate but
    ultimately useless. Tracks time wasted per attacker in Neo4j.
    """

    def __init__(self) -> None:
        self._wasters: list[dict[str, Any]] = []
        self._attacker_time: dict[str, int] = {}  # attacker_ip → estimated seconds wasted

    # ── FAKE DATABASE DUMP ──────────────────────────────────────────

    def generate_fake_database(self, name: str = "production", rows: int = 1000) -> dict[str, Any]:
        """Generate a fake SQL dump with realistic-looking data.

        Creates multiple tables with believable data that leads nowhere.
        """
        tables = random.sample(FAKE_TABLE_NAMES, k=min(5, len(FAKE_TABLE_NAMES)))
        sql_lines = [
            f"-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)",
            f"-- Host: 10.0.2.15    Database: {name}",
            f"-- ------------------------------------------------------",
            f"-- Server version\t8.0.35 MySQL Community Server - GPL",
            "",
            f"DROP DATABASE IF EXISTS `{name}`;",
            f"CREATE DATABASE `{name}`;",
            f"USE `{name}`;",
            "",
        ]

        total_rows = 0
        for table in tables:
            # CREATE TABLE
            sql_lines.append(f"-- Table structure for table `{table}`")
            sql_lines.append(f"DROP TABLE IF EXISTS `{table}`;")
            sql_lines.append(f"CREATE TABLE `{table}` (")

            if table == "users":
                sql_lines.extend([
                    f"  `id` int NOT NULL AUTO_INCREMENT,",
                    f"  `username` varchar(64) NOT NULL,",
                    f"  `email` varchar(255) NOT NULL,",
                    f"  `password_hash` varchar(255) NOT NULL,",
                    f"  `role` enum('admin','user','service') DEFAULT 'user',",
                    f"  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,",
                    f"  `last_login` timestamp NULL DEFAULT NULL,",
                    f"  PRIMARY KEY (`id`),",
                    f"  UNIQUE KEY `username` (`username`),",
                    f"  UNIQUE KEY `email` (`email`)",
                    f") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                ])
            elif table == "orders":
                sql_lines.extend([
                    f"  `id` int NOT NULL AUTO_INCREMENT,",
                    f"  `user_id` int NOT NULL,",
                    f"  `product_id` int NOT NULL,",
                    f"  `amount` decimal(10,2) NOT NULL,",
                    f"  `status` enum('pending','completed','refunded','cancelled') DEFAULT 'pending',",
                    f"  `payment_method` varchar(50) DEFAULT NULL,",
                    f"  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,",
                    f"  PRIMARY KEY (`id`),",
                    f"  KEY `user_id` (`user_id`),",
                    f"  KEY `product_id` (`product_id`)",
                    f") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                ])
            elif table == "api_keys":
                sql_lines.extend([
                    f"  `id` int NOT NULL AUTO_INCREMENT,",
                    f"  `service` varchar(64) NOT NULL,",
                    f"  `key_value` varchar(255) NOT NULL,",
                    f"  `active` tinyint(1) DEFAULT '1',",
                    f"  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,",
                    f"  `expires_at` timestamp NULL DEFAULT NULL,",
                    f"  PRIMARY KEY (`id`),",
                    f"  KEY `service` (`service`)",
                    f") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                ])
            else:
                sql_lines.extend([
                    f"  `id` int NOT NULL AUTO_INCREMENT,",
                    f"  `name` varchar(128) DEFAULT NULL,",
                    f"  `data` text,",
                    f"  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,",
                    f"  PRIMARY KEY (`id`)",
                    f") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                ])

            sql_lines.append("")

            # INSERT statements
            table_rows = min(rows // len(tables), 200)
            total_rows += table_rows

            if table == "users":
                sql_lines.append(f"-- Dumping data for table `{table}`")
                sql_lines.append(f"LOCK TABLES `{table}` WRITE;")
                sql_lines.append(f"INSERT INTO `{table}` VALUES")
                for i in range(1, table_rows + 1):
                    fn = random.choice(FAKE_FIRST_NAMES)
                    ln = random.choice(FAKE_LAST_NAMES)
                    username = f"{fn[0].lower()}{ln.lower()}{random.randint(1, 99)}"
                    email = f"{username}@{random.choice(FAKE_DOMAINS)}"
                    pw_hash = f"$2b$12${self._rand_hex(22)}....{self._rand_hex(8)}"
                    role = random.choice(["admin", "user", "user", "user", "service"])
                    created = self._rand_date()
                    last_login = self._rand_date()
                    line = f"({i}, '{username}', '{email}', '{pw_hash}', '{role}', '{created}', '{last_login}')"
                    if i < table_rows:
                        line += ","
                    else:
                        line += ";"
                    sql_lines.append(line)
                sql_lines.append("UNLOCK TABLES;")
            elif table == "api_keys":
                sql_lines.append(f"-- Dumping data for table `{table}`")
                sql_lines.append(f"LOCK TABLES `{table}` WRITE;")
                sql_lines.append(f"INSERT INTO `{table}` VALUES")
                for i in range(1, table_rows + 1):
                    service = random.choice(["stripe", "sendgrid", "slack", "twilio", "github", "aws"])
                    key = self._rand_api_key()
                    active = random.choice([1, 1, 0])
                    created = self._rand_date()
                    expires = "NULL" if random.random() < 0.5 else f"'{self._rand_date()}'"
                    line = f"({i}, '{service}', '{key}', {active}, '{created}', {expires})"
                    if i < table_rows:
                        line += ","
                    else:
                        line += ";"
                    sql_lines.append(line)
                sql_lines.append("UNLOCK TABLES;")
            else:
                sql_lines.append(f"-- Dumping data for table `{table}`")
                sql_lines.append(f"LOCK TABLES `{table}` WRITE;")
                sql_lines.append(f"INSERT INTO `{table}` VALUES")
                for i in range(1, table_rows + 1):
                    name = f"{random.choice(FAKE_FIRST_NAMES)} {random.choice(FAKE_LAST_NAMES)}"
                    data = self._rand_hex(random.randint(8, 32))
                    created = self._rand_date()
                    line = f"({i}, '{name}', '{data}', '{created}')"
                    if i < table_rows:
                        line += ","
                    else:
                        line += ";"
                    sql_lines.append(line)
                sql_lines.append("UNLOCK TABLES;")

            sql_lines.append("")

        sql_lines.append(f"-- Dump completed on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")

        result = {
            "waster_id": f"tw_db_{int(datetime.now(timezone.utc).timestamp())}",
            "waster_type": "database",
            "database_name": name,
            "tables": tables,
            "total_rows": total_rows,
            "sql": "\n".join(sql_lines),
            "estimated_size_kb": len("\n".join(sql_lines)) // 1024,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_waster(result)
        logger.info("BRAINMAZE: Generated fake database dump '%s' with %d rows across %d tables",
                    name, total_rows, len(tables))
        return result

    # ── FAKE FILESYSTEM ─────────────────────────────────────────────

    def generate_fake_filesystem(self, depth: int = 3) -> dict[str, Any]:
        """Generate a fake directory listing with interesting filenames."""
        def _gen_tree(current_depth: int, path: str) -> dict[str, Any]:
            if current_depth >= depth:
                return {"type": "dir", "path": path, "children": []}

            children = []
            # Add some files
            num_files = random.randint(3, 8)
            for _ in range(num_files):
                filename = random.choice(FAKE_FILENAMES)
                size = random.randint(64, 50_000_000)
                children.append({
                    "type": "file",
                    "path": f"{path}/{filename}",
                    "size": size,
                    "permissions": random.choice(["644", "600", "755", "400"]),
                    "owner": random.choice(["root", "deploy", "www-data", "admin"]),
                    "modified": self._rand_date(),
                })

            # Add subdirectories
            if current_depth < depth - 1:
                num_dirs = random.randint(2, 4)
                dir_names = ["backup", "config", "logs", "tmp", "cache", "data",
                             "secrets", "archive", "scripts", "deploy", "docker",
                             "nginx", "ssl", "ssh", "api", "static", "uploads"]
                for dir_name in random.sample(dir_names, k=min(num_dirs, len(dir_names))):
                    child_path = f"{path}/{dir_name}"
                    children.append(_gen_tree(current_depth + 1, child_path))

            return {"type": "dir", "path": path, "children": children}

        tree = _gen_tree(0, "/var/www/company")

        # Count items
        def _count(node: dict) -> tuple[int, int]:
            files, dirs = 0, 0
            for child in node.get("children", []):
                if child["type"] == "file":
                    files += 1
                else:
                    dirs += 1
                    f, d = _count(child)
                    files += f
                    dirs += d
            return files, dirs

        file_count, dir_count = _count(tree)

        result = {
            "waster_id": f"tw_fs_{int(datetime.now(timezone.utc).timestamp())}",
            "waster_type": "filesystem",
            "root": "/var/www/company",
            "tree": tree,
            "total_files": file_count,
            "total_dirs": dir_count,
            "depth": depth,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_waster(result)
        logger.info("BRAINMAZE: Generated fake filesystem (depth=%d, files=%d, dirs=%d)",
                    depth, file_count, dir_count)
        return result

    # ── FAKE API DOCS ───────────────────────────────────────────────

    def generate_fake_api_docs(self) -> dict[str, Any]:
        """Generate fake API documentation with endpoints that don't exist."""
        endpoints = [
            {
                "method": "GET", "path": "/api/v1/users",
                "description": "List all users",
                "auth": "Bearer JWT",
                "params": {"page": "int", "limit": "int", "filter": "string"},
                "response": '{"users": [...], "total": 1234, "page": 1}',
            },
            {
                "method": "POST", "path": "/api/v1/users",
                "description": "Create a new user",
                "auth": "Bearer JWT (admin only)",
                "params": {"username": "string", "email": "string", "role": "string"},
                "response": '{"id": 123, "username": "...", "created": true}',
            },
            {
                "method": "GET", "path": "/api/v1/users/{id}",
                "description": "Get user details",
                "auth": "Bearer JWT",
                "params": {"id": "int"},
                "response": '{"id": 123, "username": "...", "email": "...", "role": "..."}',
            },
            {
                "method": "DELETE", "path": "/api/v1/users/{id}",
                "description": "Delete a user",
                "auth": "Bearer JWT (admin only)",
                "params": {"id": "int"},
                "response": '{"deleted": true}',
            },
            {
                "method": "GET", "path": "/api/v1/payments",
                "description": "List all payments",
                "auth": "Bearer JWT (admin)",
                "params": {"status": "string", "date_from": "date", "date_to": "date"},
                "response": '{"payments": [...], "total_amount": "12345.67"}',
            },
            {
                "method": "POST", "path": "/api/v1/payments/process",
                "description": "Process a payment",
                "auth": "Bearer JWT",
                "params": {"amount": "float", "currency": "string", "method": "string"},
                "response": '{"transaction_id": "...", "status": "completed"}',
            },
            {
                "method": "GET", "path": "/api/v1/admin/config",
                "description": "Get system configuration (SENSITIVE)",
                "auth": "Bearer JWT (superadmin)",
                "params": {},
                "response": '{"database": {...}, "redis": {...}, "secrets": {...}}',
            },
            {
                "method": "POST", "path": "/api/v1/admin/exec",
                "description": "Execute system command (DANGEROUS)",
                "auth": "Bearer JWT (superadmin)",
                "params": {"command": "string"},
                "response": '{"output": "...", "exit_code": 0}',
            },
            {
                "method": "GET", "path": "/api/v1/export/{table}",
                "description": "Export table data",
                "auth": "Bearer JWT (admin)",
                "params": {"table": "string", "format": "csv|json|xml"},
                "response": '{"download_url": "...", "expires_in": 3600}',
            },
            {
                "method": "POST", "path": "/api/v1/auth/login",
                "description": "Authenticate user",
                "auth": "None",
                "params": {"username": "string", "password": "string"},
                "response": '{"token": "...", "expires_in": 3600}',
            },
            {
                "method": "POST", "path": "/api/v1/auth/refresh",
                "description": "Refresh authentication token",
                "auth": "Bearer JWT",
                "params": {},
                "response": '{"token": "...", "expires_in": 3600}',
            },
            {
                "method": "GET", "path": "/api/v1/internal/debug",
                "description": "Debug endpoint (should not be public)",
                "auth": "None",
                "params": {"verbose": "bool"},
                "response": '{"env": {...}, "config": {...}, "connections": [...]}',
            },
            {
                "method": "GET", "path": "/api/v1/internal/health",
                "description": "Health check",
                "auth": "None",
                "params": {},
                "response": '{"status": "healthy", "services": {...}}',
            },
        ]

        markdown = "# API Documentation\n\n"
        markdown += f"> Base URL: https://api.corp.local\n"
        markdown += f"> Version: 2.4.1\n"
        markdown += f"> Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n\n"
        markdown += "## Authentication\n\n"
        markdown += "All endpoints except `/auth/login` require a Bearer JWT token.\n"
        markdown += "Admin endpoints require `role: admin` or `role: superadmin`.\n\n"

        for ep in endpoints:
            markdown += f"### {ep['method']} {ep['path']}\n\n"
            markdown += f"{ep['description']}\n\n"
            markdown += f"**Auth:** {ep['auth']}\n\n"
            if ep["params"]:
                markdown += "**Parameters:**\n\n"
                markdown += "| Parameter | Type |\n|-----------|------|\n"
                for param, ptype in ep["params"].items():
                    markdown += f"| `{param}` | {ptype} |\n"
                markdown += "\n"
            markdown += f"**Response:**\n```json\n{ep['response']}\n```\n\n---\n\n"

        result = {
            "waster_id": f"tw_api_{int(datetime.now(timezone.utc).timestamp())}",
            "waster_type": "api_docs",
            "endpoints": endpoints,
            "markdown": markdown,
            "endpoint_count": len(endpoints),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_waster(result)
        logger.info("BRAINMAZE: Generated fake API docs with %d endpoints", len(endpoints))
        return result

    # ── FAKE SOURCE CODE ────────────────────────────────────────────

    def generate_fake_source_code(self, filename: str = "app.py") -> dict[str, Any]:
        """Generate fake source code with fake vulnerabilities."""
        code_templates = {
            "app.py": '''#!/usr/bin/env python3
"""Production API server — DO NOT MODIFY WITHOUT APPROVAL"""

from flask import Flask, request, jsonify
import os
import subprocess
import pickle
import MySQLdb
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-me')
app.config['DATABASE'] = {
    'host': '10.0.2.15',
    'user': 'admin',
    'password': 'S3cureP@ss!',
    'db': 'production'
}

# TODO: Remove debug mode before production deploy
app.config['DEBUG'] = True

@app.route('/api/v1/users')
def get_users():
    # FIXME: Add authentication
    user_id = request.args.get('id', '')
    # NOTE: SQL injection possible here — need to fix
    query = f"SELECT * FROM users WHERE id = {user_id}"
    db = MySQLdb.connect(**app.config['DATABASE'])
    cursor = db.cursor()
    cursor.execute(query)
    return jsonify({'users': cursor.fetchall()})

@app.route('/api/v1/exec', methods=['POST'])
def exec_command():
    # DEBUG ONLY — should be removed
    cmd = request.json.get('command', '')
    result = subprocess.check_output(cmd, shell=True)
    return jsonify({'output': result.decode()})

@app.route('/api/v1/upload', methods=['POST'])
def upload_file():
    # TODO: Validate file type
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')
    return jsonify({'status': 'uploaded', 'path': f'/uploads/{file.filename}'})

@app.route('/api/v1/deserialize', methods=['POST'])
def deserialize_data():
    # WARNING: pickle is unsafe
    data = request.data
    obj = pickle.loads(data)
    return jsonify({'result': str(obj)})

@app.route('/api/v1/internal/debug')
def debug_info():
    # SHOULD NOT BE PUBLIC
    return jsonify({
        'env': dict(os.environ),
        'config': {k: str(v) for k, v in app.config.items()},
        'secret_key': app.config['SECRET_KEY'],
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
''',
            "database.js": '''const { Pool } = require('pg');
const fs = require('fs');

// Database configuration — hardcoded for convenience
const pool = new Pool({
  host: '10.0.2.15',
  port: 5432,
  user: 'admin',
  password: 'S3cureP@ss!',
  database: 'production',
  ssl: false,  // TODO: enable SSL
});

// Execute raw query (VULNERABLE — no parameterization)
async function query(sql, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(sql, params);
    return result.rows;
  } finally {
    client.release();
  }
}

// User search — SQL INJECTION VULNERABILITY
async function searchUsers(searchTerm) {
  // FIXME: This is vulnerable to SQL injection
  return query(`SELECT * FROM users WHERE username LIKE '%${searchTerm}%'`);
}

// Admin endpoint — no auth check
async function getAllUsers() {
  return query('SELECT * FROM users');
}

// Export all users to file — path traversal possible
async function exportUsers(filename) {
  const users = await getAllUsers();
  const filepath = `/var/www/exports/${filename}`;
  fs.writeFileSync(filepath, JSON.stringify(users));
  return filepath;
}

module.exports = { query, searchUsers, getAllUsers, exportUsers };
''',
            "auth.go": '''package auth

import (
    "database/sql"
    "fmt"
    "net/http"
    "os"
    _ "github.com/lib/pq"
)

// Hardcoded credentials — should use env vars
const DBHost = "10.0.2.15"
const DBUser = "admin"
const DBPass = "S3cureP@ss!"
const DBName = "production"

// LoginHandler — SQL INJECTION via username field
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    // VULNERABLE: string concatenation in SQL
    query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'",
        username, password)

    db, err := sql.Open("postgres", fmt.Sprintf("host=%s user=%s password=%s dbname=%s",
        DBHost, DBUser, DBPass, DBName))
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    var id int
    err = db.QueryRow(query).Scan(&id)
    if err != nil {
        // Information leak — tells user if username exists
        if err == sql.ErrNoRows {
            http.Error(w, "User not found", 401)
        } else {
            http.Error(w, "Wrong password", 401)
        }
        return
    }

    // No session management — just return user ID
    fmt.Fprintf(w, "Logged in as user %d", id)
}

// JWT secret hardcoded
var jwtSecret = []byte("super-secret-jwt-key-2024")

// TODO: Implement proper session management
// TODO: Add rate limiting
// TODO: Add CSRF protection
''',
        }

        # Pick a template or use the requested filename
        if filename in code_templates:
            code = code_templates[filename]
        else:
            code = code_templates.get("app.py", code_templates["app.py"])

        # Fake vulnerabilities in the code
        vulns = [
            {"type": "SQL Injection", "line": 18, "description": "Unparameterized SQL query with user input"},
            {"type": "Command Injection", "line": 27, "description": "subprocess.check_output with shell=True and user input"},
            {"type": "Path Traversal", "line": 35, "description": "Unvalidated filename in file save path"},
            {"type": "Insecure Deserialization", "line": 42, "description": "pickle.loads on untrusted data"},
            {"type": "Information Disclosure", "line": 49, "description": "Debug endpoint exposes environment variables and secrets"},
            {"type": "Hardcoded Credentials", "line": 15, "description": "Database credentials hardcoded in source"},
            {"type": "Debug Mode Enabled", "line": 14, "description": "Flask DEBUG=True in production"},
        ]

        result = {
            "waster_id": f"tw_code_{int(datetime.now(timezone.utc).timestamp())}",
            "waster_type": "source_code",
            "filename": filename,
            "code": code,
            "language": "python" if filename.endswith(".py") else "javascript" if filename.endswith(".js") else "go",
            "fake_vulnerabilities": vulns,
            "vuln_count": len(vulns),
            "lines": code.count("\n") + 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_waster(result)
        logger.info("BRAINMAZE: Generated fake source code '%s' with %d fake vulnerabilities",
                    filename, len(vulns))
        return result

    # ── FAKE GIT REPO ────────────────────────────────────────────────

    def generate_fake_git_repo(self) -> dict[str, Any]:
        """Generate a fake .git directory with fake commit history."""
        num_commits = random.randint(15, 40)
        commits = []
        authors = [
            ("Dave Mitchell", "dave.mitchell@corp.local"),
            ("Sarah Chen", "sarah.chen@corp.local"),
            ("Mike Torres", "mike.torres@corp.local"),
            ("Jenkins Bot", "jenkins@corp.local"),
            ("Deploy Service", "deploy@corp.local"),
        ]

        base_time = datetime.now(timezone.utc) - timedelta(days=180)

        for i in range(num_commits):
            commit_time = base_time + timedelta(
                days=random.randint(0, 180),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
            )
            author = random.choice(authors)
            commit_hash = self._rand_hex(40)

            messages = [
                "Fix authentication bug in login handler",
                "Update database configuration for production",
                "Add new API endpoint for user management",
                "Remove debug mode from production config",
                "Fix SQL injection vulnerability in search",
                "Update dependencies to latest versions",
                "Add rate limiting to auth endpoints",
                "Fix CORS configuration",
                "Update SSL certificates",
                "Add input validation for user registration",
                "Fix memory leak in connection pool",
                "Update JWT secret key",
                "Add audit logging for admin actions",
                "Fix race condition in payment processing",
                "Remove hardcoded credentials from source",
                "Add security headers to all responses",
                "Fix path traversal in file upload",
                "Update password hashing to bcrypt",
                "Add CSRF protection to forms",
                "Fix XSS vulnerability in user profile",
                "Update Docker configuration",
                "Add health check endpoint",
                "Fix session management bug",
                "Update nginx configuration",
                "Add API documentation",
                "Fix broken deployment script",
                "Update environment variables",
                "Add input sanitization",
                "Fix broken CI/CD pipeline",
                "Update logging configuration",
            ]

            files_changed = random.sample(
                ["app.py", "database.js", "auth.go", "config.yml", ".env",
                 "docker-compose.yml", "nginx.conf", "requirements.txt",
                 "package.json", "Dockerfile", "README.md", "Makefile",
                 "migrations/001_initial.sql", "migrations/002_users.sql",
                 "tests/test_auth.py", "tests/test_api.py"],
                k=random.randint(1, 5),
            )

            commit = {
                "hash": commit_hash,
                "author": author[0],
                "email": author[1],
                "date": commit_time.strftime("%a %b %d %H:%M:%S %Y %z"),
                "message": random.choice(messages),
                "files_changed": files_changed,
                "insertions": random.randint(5, 500),
                "deletions": random.randint(0, 200),
            }
            commits.append(commit)

        # Sort by date
        commits.sort(key=lambda c: c["date"], reverse=True)

        # Generate fake branches
        branches = [
            {"name": "main", "head": commits[0]["hash"]},
            {"name": "develop", "head": commits[min(5, len(commits) - 1)]["hash"]},
            {"name": "feature/auth-refactor", "head": commits[min(10, len(commits) - 1)]["hash"]},
            {"name": "hotfix/sql-injection", "head": commits[min(3, len(commits) - 1)]["hash"]},
        ]

        # Generate fake tags
        tags = [
            {"name": "v2.4.1", "commit": commits[0]["hash"], "message": "Production release 2.4.1"},
            {"name": "v2.4.0", "commit": commits[min(5, len(commits) - 1)]["hash"], "message": "Production release 2.4.0"},
            {"name": "v2.3.0", "commit": commits[min(15, len(commits) - 1)]["hash"], "message": "Production release 2.3.0"},
        ]

        result = {
            "waster_id": f"tw_git_{int(datetime.now(timezone.utc).timestamp())}",
            "waster_type": "git_repo",
            "commits": commits,
            "commit_count": len(commits),
            "branches": branches,
            "tags": tags,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        self._store_waster(result)
        logger.info("BRAINMAZE: Generated fake git repo with %d commits, %d branches, %d tags",
                    len(commits), len(branches), len(tags))
        return result

    # ── TIME TRACKING ───────────────────────────────────────────────

    def record_time_wasted(self, attacker_ip: str, seconds: int) -> None:
        """Record time wasted by an attacker on decoy content."""
        self._attacker_time[attacker_ip] = self._attacker_time.get(attacker_ip, 0) + seconds
        try:
            cypher_write(
                """
                MERGE (a:AttackerTime {ip: $ip})
                SET a.time_wasted = a.time_wasted + $seconds,
                    a.last_updated = $timestamp
                """,
                {"ip": attacker_ip, "seconds": seconds, "timestamp": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as e:
            logger.debug("BRAINMAZE: Neo4j time tracking failed (non-critical): %s", e)

    def get_time_wasted(self, attacker_ip: str | None = None) -> dict[str, Any]:
        """Get time wasted statistics."""
        if attacker_ip:
            return {"attacker_ip": attacker_ip, "time_wasted_seconds": self._attacker_time.get(attacker_ip, 0)}
        return {
            "total_attackers": len(self._attacker_time),
            "total_time_wasted_seconds": sum(self._attacker_time.values()),
            "per_attacker": dict(self._attacker_time),
        }

    # ── STATUS ──────────────────────────────────────────────────────

    def get_all_wasters(self) -> list[dict[str, Any]]:
        """Get all generated time wasters."""
        return list(self._wasters)

    # ── INTERNAL ─────────────────────────────────────────────────────

    def _store_waster(self, waster: dict[str, Any]) -> None:
        """Store waster in memory and Neo4j."""
        self._wasters.append(waster)
        if len(self._wasters) > 500:
            self._wasters = self._wasters[-500:]

    def _rand_hex(self, n: int) -> str:
        return "".join(random.choices("0123456789abcdef", k=n))

    def _rand_api_key(self) -> str:
        prefix = random.choice(["sk-proj-", "sk_live_", "SG.", "xoxb-", "ghp_"])
        return prefix + "".join(random.choices(string.ascii_letters + string.digits, k=32))

    def _rand_date(self) -> str:
        start = datetime(2023, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 12, 31, tzinfo=timezone.utc)
        delta = end - start
        random_delta = timedelta(seconds=random.randint(0, int(delta.total_seconds())))
        return (start + random_delta).strftime("%Y-%m-%d %H:%M:%S")


# ── Singleton ────────────────────────────────────────────────────────────

_generator: Optional[TimeWasterGenerator] = None


def get_time_waster_generator() -> TimeWasterGenerator:
    global _generator
    if _generator is None:
        _generator = TimeWasterGenerator()
    return _generator