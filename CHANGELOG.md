# Changelog

All notable changes to Security Hardening are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
plugin uses [Semantic Versioning](https://semver.org/):

- **MAJOR** — changes that can break a site (removed features, changed behaviour sites rely on).
- **MINOR** — new protections or features.
- **PATCH** — bug fixes.

## [Unreleased]

## [1.4.0] - 2026-11-01

Fixes from the first client site built on the starter template (svenssonsmetropol).

### Security
- A display name that equals the login name (WordPress's default) is replaced by the user's name, nickname or the site name on registration and profile updates. The display name is shown in bylines, JSON-LD and RSS, so it leaked the login name. Existing users are fixed once, the first time an administrator opens wp-admin after the update.
- Password spraying: when an IP has failed against 10 different accounts within 15 minutes, it may not try any new accounts for 15 minutes. Accounts known from that IP — those that tried during the window or logged in successfully from it within 30 days — keep working with the per-account rule, so regular users can still log in behind a shared CDN/proxy IP during an attack. Filter: `security_hardening_max_accounts_per_ip` (0 turns it off).
- Security headers (`nosniff`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options`) are also sent on `wp-login.php` and in wp-admin.
- Admin notifications are based on capabilities instead of the role names administrator/editor, so custom roles with high capabilities, extra roles, `add_cap()` and super admin are covered too. Filter: `security_hardening_privileged_caps`.

## [1.3.2] - 2026-11-01

No change to the plugin itself — repo tooling only.

### Changed
- Releases are tagged automatically by a GitHub Action from the version in the plugin header.
- All Claude files are ignored by git.

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
