# Certbot DNS Forpsi Plugin

A Certbot plugin to complete DNS-01 challenges by automatically managing TXT records for domains registered with Forpsi.

Since Forpsi does not provide an API for DNS management, this plugin interacts with the Forpsi admin web interface to add and remove TXT records required for Let's Encrypt certificate issuance. This means if Forpsi changes their admin interface, the plugin may break and require updates. Please report any issues you encounter.

**Inspiration**: This project was inspired by [AreYouLoco's Forpsi acme.sh script](https://gist.github.com/AreYouLoco/9dc62e7067c60107875903d2bd54e2e0).

> **⚠️ Beta Software Disclaimer**
> 
> This plugin is currently in beta status. It has been tested and confirmed to work with `admin.forpsi.hu`. Further testing is needed for other Forpsi admin sites. Please report any issues you encounter.
> 
> **Development Note**: Inital Forpsi admin site "API" testing was conducted by me (Ákos Szabados), but most of the coding was done using Claude Code.

## Features

- Automated DNS-01 challenge completion via Forpsi admin interface
- Support for multiple Forpsi admin sites
- Two-factor authentication (TOTP) support
- Automatic domain ID discovery for subdomains
- Multiple TXT record management (add/delete)
- CLI parameter support as alternative to credentials file

## Installation

### From PyPI

Install the plugin directly from PyPI:

```bash
pip install certbot-dns-forpsi
```

### From Source

Clone the repository and install:

```bash
pip install .
```

## Usage

### Method 1: Using credentials file

1. Create credentials file:
```bash
cp forpsi-credentials.ini.example forpsi-credentials.ini
```

2. Edit `forpsi-credentials.ini` with your Forpsi credentials

3. Set appropriate permissions:
```bash
chmod 600 forpsi-credentials.ini
```

4. Run Certbot:
```bash
certbot certonly \
  --authenticator dns-forpsi \
  --dns-forpsi-credentials ./forpsi-credentials.ini \
  --dns-forpsi-propagation-seconds 120 \
  -d example.com \
  -d *.example.com
```

### Method 2: Using CLI parameters

```bash
certbot certonly \
  --authenticator dns-forpsi \
  --dns-forpsi-admin-site admin.forpsi.com \
  --dns-forpsi-username your_username \
  --dns-forpsi-password your_password \
  --dns-forpsi-totp-secret your_totp_secret \
  --dns-forpsi-propagation-seconds 120 \
  -d example.com
```

## Configuration Options

- `--dns-forpsi-credentials`: Path to Forpsi credentials INI file
- `--dns-forpsi-admin-site`: Forpsi admin site (e.g., admin.forpsi.com)
- `--dns-forpsi-username`: Forpsi username (alternative to credentials file)
- `--dns-forpsi-password`: Forpsi password (alternative to credentials file)
- `--dns-forpsi-totp-secret`: TOTP secret for 2FA (optional)
- `--dns-forpsi-propagation-seconds`: DNS propagation delay (default: 120 seconds)

## Credentials File Format

Create a `forpsi-credentials.ini` file with the following format:

```ini
certbot_dns_forpsi:dns_forpsi_admin_site = admin.forpsi.com
certbot_dns_forpsi:dns_forpsi_username = your_username
certbot_dns_forpsi:dns_forpsi_password = your_password
certbot_dns_forpsi:dns_forpsi_totp_secret = your_totp_secret
```

## Two-Factor Authentication

If you have 2FA enabled on your Forpsi account, provide your TOTP secret:
- Get your TOTP secret from your authenticator app setup
- Add it to the credentials file or use the `--dns-forpsi-totp-secret` parameter

## How It Works

1. **Authentication**: Authenticates with Forpsi admin interface using username/password and optional TOTP
2. **Domain Discovery**: Automatically discovers domain IDs by parsing the domain list page
3. **TXT Record Management**: Adds/removes TXT records through the admin interface
4. **Verification**: Verifies record creation/deletion by checking the admin interface

## Development

To install in development mode:
```bash
pip install -e .
```

## Testing

Test with Let's Encrypt staging environment:
```bash
certbot certonly \
  --authenticator dns-forpsi \
  --dns-forpsi-credentials ./forpsi-credentials.ini \
  --test-cert \
  -d example.com
```

