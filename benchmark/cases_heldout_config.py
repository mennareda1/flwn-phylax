"""
benchmark/cases_heldout_config.py

THE configuration-file HELD-OUT cases for the secrets scanner (security_service/core/config_secrets.py). Written on 2026-11-11 AFTER the detector was frozen (fingerprint of
config_secrets.py in the report) and WITHOUT running the detector on any of them. They are for ONE final run:

    python -m benchmark.config_eval --heldout

Rules of this file, the same as the other held-out sets:
  - Nothing here is used to tune the detector. If the final run misses something, it is reported as a miss, not fixed and re-run: the set would no longer be held out.
  - The fingerprint is pinned below. The evaluation refuses a final verdict if a single character here changed.
  - 20 vulnerable files and 20 safe ones, whole realistic files (not one-liners), across JSON, YAML, TOML, INI, properties, XML .config and text.
  - The safe files are full of credential-sounding words (labels, secretKeyRef, CI secret references, encrypted vaults, lockfile hashes), because that is where scanners misfire.
  - TWO vulnerable files are outside the detector's design ON PURPOSE (an abbreviated key name, a pure dictionary passphrase), so the measured rate is not flattered.
  - HONEST LIMIT: the author of the detector also wrote these cases. The set is held out from tuning, not from the author's own idea of what a secret looks like.
"""

from __future__ import annotations

import hashlib


# Three of the fake secrets below are in the exact format of real provider tokens, which makes GitHub's push protection refuse the file. They are assembled here from pieces, so the
# source text never contains the whole token while the case text (and therefore the fingerprint) is exactly what it was. None of them is a real credential.
_PIECES = {
    "%%AWS_KEY_ID%%": "AKIA" + "J3Q7XMPLZ4R5T6UV",
    "%%AWS_SECRET%%": "kT3p9Xz/2VqLmN8c" + "Yb7dRf4HsWj0AeUoGiPx1EtZ",
    "%%SLACK_TOKEN%%": "xo" + "xb-123456789012-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx",
}


def _case(case_id: str, kind: str, fmt: str, path: str, note: str, code: str) -> dict:
    for placeholder, value in _PIECES.items():
        code = code.replace(placeholder, value)
    return {"id": case_id, "kind": kind, "category": fmt, "path": path, "note": note, "code": code, "group": "heldout"}


# After the cases are written, `python -m benchmark.cases_heldout_config` prints the fingerprint and demo() fails until it is pinned here.
PINNED_FINGERPRINT = "046d0b1e5d2d"

HELDOUT_CASES: list[dict] = [
    _case('hc-compose-mysql', 'vulnerable', 'yaml', 'docker-compose.yml', 'root password written into a compose environment list', r'''
services:
  db:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      - MYSQL_DATABASE=shop
      - MYSQL_ROOT_PASSWORD=Rt9!mysqlRoot
    ports:
      - "3306:3306"
'''),
    _case('hc-spring-datasource', 'vulnerable', 'properties', 'src/main/resources/application.properties', 'datasource password in a Spring properties file', r'''
server.port=8080
spring.application.name=orders
spring.datasource.url=jdbc:postgresql://db.internal:5432/orders
spring.datasource.username=orders_app
spring.datasource.password=Qw3rty!2024x
spring.jpa.hibernate.ddl-auto=validate
'''),
    _case('hc-appsettings-connstr', 'vulnerable', 'json', 'appsettings.json', 'SQL Server connection string with an inline password', r'''
{
  "Logging": { "LogLevel": { "Default": "Information" } },
  "ConnectionStrings": {
    "Default": "Server=sql01;Database=Billing;User Id=billing_app;Password=Str0ng!Pass77;TrustServerCertificate=True;"
  },
  "AllowedHosts": "*"
}
'''),
    _case('hc-toml-database', 'vulnerable', 'toml', 'config/settings.toml', 'database password in a TOML table', r'''
title = "inventory"

[server]
host = "0.0.0.0"
port = 9000

[database]
host = "db.internal"
user = "inventory"
password = "4n0th3rS3cret"
pool_size = 10
'''),
    _case('hc-ini-smtp', 'vulnerable', 'ini', 'conf/mail.ini', 'SMTP relay password in an INI section', r'''
[smtp]
host = smtp.mailrelay.example
port = 587
user = notifications
password = Sm7p!relay2024
use_tls = true
'''),
    _case('hc-serverless-aws', 'vulnerable', 'yaml', 'serverless.yml', 'an AWS secret access key (contains slashes) in a function environment', r'''
service: report-worker
provider:
  name: aws
  runtime: nodejs20.x
  environment:
    AWS_REGION: eu-west-1
    AWS_ACCESS_KEY_ID: %%AWS_KEY_ID%%
    AWS_SECRET_ACCESS_KEY: %%AWS_SECRET%%
functions:
  run:
    handler: handler.run
'''),
    _case('hc-k8s-secret', 'vulnerable', 'yaml', 'deploy/db-secret.yaml', 'a Kubernetes Secret with a base64 password (base64 is encoding, not protection)', r'''
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: shop
type: Opaque
data:
  username: c2hvcF9hcHA=
  password: UzNjcjN0UGFzczk5IQ==
'''),
    _case('hc-github-token-yaml', 'vulnerable', 'yaml', 'config/ci.yaml', 'a GitHub personal access token in a CI settings file', r'''
repository: acme/widgets
branch: main
publish:
  registry: ghcr.io
  token: ghp_k4Dm8Qx2Zr7Vb1Nc5Ws9Tf3Yh6Jg0Lp2Aa4
'''),
    _case('hc-private-key-block', 'vulnerable', 'yaml', 'config/tls.yaml', 'a private key embedded in a YAML block scalar', r'''
tls:
  enabled: true
  certificate: /etc/ssl/certs/app.pem
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun
    VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK
    -----END RSA PRIVATE KEY-----
'''),
    _case('hc-oauth-json', 'vulnerable', 'json', 'config/oauth.json', 'an OAuth client secret next to a harmless client id', r'''
{
  "provider": "example-idp",
  "client_id": "web-dashboard",
  "client_secret": "s9Vq3LmX7pT2zKd8RwY4",
  "redirect_uri": "https://app.example.com/callback",
  "scopes": ["openid", "profile"]
}
'''),
    _case('hc-commented-old-password', 'vulnerable', 'yaml', 'config/database.yml', 'an old password left in a comment, still a leaked credential', r'''
production:
  adapter: postgresql
  host: db.internal
  username: app
  # old password: Hunter2!Prod2023
  password: ${DATABASE_PASSWORD}
'''),
    _case('hc-xml-appsettings', 'vulnerable', 'config', 'web.config', 'an API secret in a .NET appSettings key', r'''
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="Environment" value="production"/>
    <add key="PaymentApiSecret" value="a8Fk29xPq0Lm41zQ"/>
  </appSettings>
</configuration>
'''),
    _case('hc-redis-url', 'vulnerable', 'ini', 'conf/cache.ini', 'a Redis URL with the password inside it', r'''
[cache]
backend = redis
url = redis://:Rd5!cachePass@10.0.0.5:6379/0
ttl_seconds = 600
'''),
    _case('hc-jdbc-query-password', 'vulnerable', 'properties', 'config/db.properties', 'a JDBC URL carrying the password in its query string', r'''
db.driver=com.mysql.cj.jdbc.Driver
db.url=jdbc:mysql://mysql.internal:3306/crm?user=crm_app&password=Cr7m!Db2024&useSSL=true
db.pool.max=20
'''),
    _case('hc-txt-deploy-notes', 'vulnerable', 'text', 'ops/deploy-notes.txt', 'deployment notes with a production password pasted in', r'''
Deploy checklist
1. Pull the latest image
2. Run the migrations
3. Set the production variables:
DB_PASSWORD=Pr0d!Deploy99
4. Restart the service
'''),
    _case('hc-firebase-service-account', 'vulnerable', 'json', 'config/service-account.json', 'a Google service account file with its private key', r'''
{
  "type": "service_account",
  "project_id": "acme-prod",
  "private_key_id": "5b3a9c1e7d2f4a6b8c0d1e2f3a4b5c6d7e8f9a0b",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGq3Zk\n-----END PRIVATE KEY-----\n",
  "client_email": "deployer@acme-prod.iam.gserviceaccount.com"
}
'''),
    _case('hc-jwt-secret-properties', 'vulnerable', 'properties', 'src/main/resources/security.properties', 'a JWT signing secret', r'''
jwt.issuer=acme-auth
jwt.expiry.minutes=30
jwt.secret=8f7d6c5b4a39281706f5e4d3c2b1a090
'''),
    _case('hc-slack-token-yaml', 'vulnerable', 'yaml', 'config/notifier.yaml', 'a Slack bot token', r'''
notifier:
  channel: "#alerts"
  slack:
    token: %%SLACK_TOKEN%%
'''),
    _case('hc-limit-abbreviated-key', 'vulnerable', 'ini', 'conf/legacy.ini', 'DESIGN LIMIT: the key is the abbreviation pw, which is not in the credential-name list', r'''
[legacy]
host = erp.internal
user = erp_batch
db_pw: Hunter2secret!
'''),
    _case('hc-limit-dictionary-passphrase', 'vulnerable', 'yaml', 'config/reports.yaml', 'DESIGN LIMIT: a pure dictionary passphrase has no digit or symbol, so it is not probable by the careful test', r'''
reports:
  schedule: nightly
  mail:
    password: correcthorsebatterystaple
'''),
    _case('hs-compose-interpolation', 'safe', 'yaml', 'docker-compose.prod.yml', 'every credential is an environment interpolation', r'''
services:
  api:
    image: acme/api:1.4
    environment:
      - DATABASE_PASSWORD=${DATABASE_PASSWORD}
      - JWT_SECRET=${JWT_SECRET:?must be set}
      - SMTP_PASSWORD
    secrets:
      - db_password
secrets:
  db_password:
    external: true
'''),
    _case('hs-spring-placeholders', 'safe', 'yaml', 'src/main/resources/application.yml', 'Spring placeholders and an encrypted value', r'''
spring:
  datasource:
    url: jdbc:postgresql://${DB_HOST:localhost}:5432/orders
    username: ${DB_USER:orders}
    password: ${DB_PASSWORD}
  mail:
    password: ENC(8Zk2LmQ9vT1pR4tYw7NxAb3CdE5fG0hJ)
'''),
    _case('hs-k8s-secretkeyref', 'safe', 'yaml', 'deploy/api-deployment.yaml', 'secrets referenced by name, never written', r'''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: acme/api:1.4
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-credentials
                  key: password
'''),
    _case('hs-gha-secrets', 'safe', 'yaml', '.github/workflows/release.yml', 'a CI workflow that only references repository secrets', r'''
name: release
on:
  push:
    tags: ["v*"]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: npm publish
'''),
    _case('hs-toml-token-url', 'safe', 'toml', 'config/auth.toml', 'credential-sounding keys that are URLs, names and lifetimes', r'''
[auth]
token_url = "https://auth.example.com/oauth/token"
token_ttl = 3600
token_type = "Bearer"
password_min_length = 12
password_policy = "strong"
secret_name = "prod/db/credentials"
'''),
    _case('hs-appsettings-empty', 'safe', 'json', 'appsettings.Development.json', 'an empty password and a trusted connection', r'''
{
  "ConnectionStrings": {
    "Default": "Server=(localdb)\\mssqllocaldb;Database=Billing;Trusted_Connection=True;"
  },
  "Smtp": { "Host": "localhost", "Password": "", "ApiKey": "" }
}
'''),
    _case('hs-ansible-vault', 'safe', 'yaml', 'group_vars/prod/vault.yml', 'an Ansible Vault encrypted value', r'''
db_user: shop_app
db_password: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  62313365396662343061393464336163383764373764613633653634306532373235303764393530
  3836393165333631376232383764646230346532376266310a626165396332656531613535363635
'''),
    _case('hs-ini-password-file', 'safe', 'ini', 'conf/db.ini', 'the password is read from a file, the file path is configured', r'''
[database]
host = db.internal
user = app
password_file = /run/secrets/db_password
'''),
    _case('hs-properties-jasypt', 'safe', 'properties', 'config/jasypt.properties', 'jasypt-encrypted values', r'''
mail.host=smtp.mailrelay.example
mail.username=notifications
mail.password=ENC(mXk7Qp2LzV9tR4yWb8NcAd3EfG1hJ0uI)
jasypt.encryptor.password=${JASYPT_PASSWORD}
'''),
    _case('hs-package-json', 'safe', 'json', 'package.json', 'scripts and dependencies that mention tokens', r'''
{
  "name": "dashboard",
  "version": "2.3.1",
  "scripts": {
    "verify-token": "node scripts/verify-token.js",
    "refresh-token": "node scripts/refresh-token.js --quiet",
    "test": "jest"
  },
  "dependencies": { "jsonwebtoken": "^9.0.2", "express": "^4.19.2" }
}
'''),
    _case('hs-readme-txt', 'safe', 'text', 'docs/SETUP.txt', 'setup instructions that talk about passwords without containing one', r'''
Setup
-----
Copy .env.example to .env and set your password and API key there.
Never commit the .env file.
If you forget your password: use the reset link on the sign-in page.
The API token expires after one hour; request a new one when it does.
'''),
    _case('hs-i18n-labels', 'safe', 'json', 'locales/en.json', 'user-interface labels', r'''
{
  "login": {
    "password": "Password",
    "forgot_password": "Forgot your password?",
    "confirm_password": "Confirm password",
    "token_expired": "Your session token has expired"
  }
}
'''),
    _case('hs-openapi-schema', 'safe', 'yaml', 'api/openapi.yaml', 'an API description that defines a password field and a bearer scheme', r'''
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  schemas:
    Login:
      type: object
      properties:
        password:
          type: string
          format: password
          minLength: 12
'''),
    _case('hs-lock-integrity', 'safe', 'yaml', 'pnpm-lock.yaml', 'lockfile integrity hashes', r'''
lockfileVersion: '9.0'
packages:
  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
'''),
    _case('hs-env-ini-empty', 'safe', 'ini', 'conf/env.ini', 'keys declared but intentionally empty', r'''
[secrets]
API_KEY=
SECRET_KEY=
DATABASE_PASSWORD=
'''),
    _case('hs-changeme-comment', 'safe', 'yaml', 'config/example.yaml', 'a placeholder with a comment telling the reader to replace it', r'''
admin:
  user: admin
  password: changeme  # replace before deploying
'''),
    _case('hs-logging-format', 'safe', 'yaml', 'config/logging.yaml', 'a log format string that mentions a token field', r'''
logging:
  format: "%(asctime)s %(levelname)s token=%(token)s %(message)s"
  level: INFO
  handlers: [console]
'''),
    _case('hs-txt-example-reference', 'safe', 'text', 'docs/config-reference.txt', 'documentation showing the shape of a setting with an angle-bracket placeholder', r'''
Configuration reference
password = <your password>
api_key = <your api key>
Set both before the first start.
'''),
    _case('hs-json-placeholders', 'safe', 'json', 'config/client.sample.json', 'a sample config whose values are obvious placeholders', r'''
{
  "apiKey": "YOUR_API_KEY",
  "clientSecret": "${CLIENT_SECRET}",
  "password": "{{ vault_password }}",
  "endpoint": "https://api.example.com/v2"
}
'''),
    _case('hs-example-password', 'safe', 'yaml', 'config/config.example.yaml', 'an example file with an obviously fake value', r'''
smtp:
  host: smtp.example.com
  user: someone
  password: example-password-123
''')
]


def config_fingerprint(cases: list[dict] = HELDOUT_CASES) -> str:
    """12 hex characters identifying exactly these cases (ids, labels, paths and contents)."""
    text = "\n".join(f"{c['id']}|{c['kind']}|{c['category']}|{c['path']}|{c['code']}" for c in cases)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def demo() -> None:
    import json
    import tomllib

    ids = [c["id"] for c in HELDOUT_CASES]
    assert len(ids) == len(set(ids)), "duplicate case id"
    assert len({c["path"] for c in HELDOUT_CASES}) == len(HELDOUT_CASES), "duplicate path"
    assert sum(c["kind"] == "vulnerable" for c in HELDOUT_CASES) == 20 and sum(c["kind"] == "safe" for c in HELDOUT_CASES) == 20
    assert {c["kind"] for c in HELDOUT_CASES} == {"vulnerable", "safe"}
    assert {c["category"] for c in HELDOUT_CASES} >= {"json", "yaml", "toml", "ini", "properties", "config", "text"}
    for case in HELDOUT_CASES:                       # a file that claims a format is valid in it (structure only: the detector is not run here)
        if case["category"] == "json":
            json.loads(case["code"])
        if case["category"] == "toml":
            tomllib.loads(case["code"])
        assert case["code"].endswith("\n") and case["note"], case["id"]
    assert sum(c["id"].startswith("hc-limit-") for c in HELDOUT_CASES) == 2          # the two deliberate design limits
    assert not any("%%" in c["code"] for c in HELDOUT_CASES), "a placeholder was not replaced"
    joined = "".join(c["code"] for c in HELDOUT_CASES)
    assert all(value in joined for value in _PIECES.values()), "a fake secret did not make it into its case"
    actual = config_fingerprint()
    assert PINNED_FINGERPRINT == actual, (
        f"the held-out cases changed: fingerprint is now {actual}, pinned {PINNED_FINGERPRINT}. If this is the first time, pin it. "
        "If the detector has already judged these cases, they are no longer held out.")
    print(f"cases_heldout_config OK: {len(HELDOUT_CASES)} cases (20 vulnerable, 20 safe) in 7 formats, valid JSON and TOML, two deliberate design limits, fingerprint {actual} pinned")


if __name__ == "__main__":
    print("fingerprint", config_fingerprint())
    demo()
