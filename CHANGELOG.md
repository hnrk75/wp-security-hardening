# Changelog

All notable changes to Security Hardening are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
plugin uses [Semantic Versioning](https://semver.org/):

- **MAJOR** — changes that can break a site (removed features, changed behaviour sites rely on).
- **MINOR** — new protections or features.
- **PATCH** — bug fixes.

## [Unreleased]

## [1.3.1] - 2026-11-01

First version as a standalone Composer package (previously `web/app/mu-plugins/security.php`
in the starter project).

### Security
- Registration is always disabled and the default role is always subscriber.
- XML-RPC and application passwords are disabled.
- Usernames are hidden from logged-out visitors (REST users endpoint, `?author=`, author archives, users sitemap, oEmbed).
- The same login error for wrong username and wrong password, and the same lost password confirmation whether the account exists or not.
- Login throttling: 5 failed logins per IP and account within 15 minutes lock that combination for 15 minutes. Works behind proxies.
- Two-factor authentication is required for all users when the Two Factor plugin is active.
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, HSTS in production over HTTPS); the WordPress version is hidden.
- Email to the admin when a user is created or becomes administrator/editor (also via `add_role()`).
