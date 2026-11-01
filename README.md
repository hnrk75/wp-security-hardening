# Security Hardening

Must-use plugin with basic WordPress security hardening. No settings, no database
tables, no server configuration — it works the same on any host.

---

## What it does

| Area | Protection |
|------|------------|
| Registration | Always disabled; the default role is always subscriber, regardless of the database settings. |
| XML-RPC | Disabled completely (brute force via `system.multicall`, pingbacks). |
| Application passwords | Disabled — they bypass the regular login and two-factor authentication. |
| Usernames | Hidden from logged-out visitors: REST `/wp/v2/users`, `?author=`, author archives, the users sitemap and oEmbed author data. |
| Login errors | The same message for wrong username and wrong password. |
| Lost password | The same confirmation whether the account exists or not. |
| Login throttling | 5 failed logins for the same account from the same IP within 15 minutes lock that combination for 15 minutes. Counting per IP **and** account means only the attacked account is locked, even behind a proxy or CDN. |
| Two-factor authentication | Required for all users when the [Two Factor](https://wordpress.org/plugins/two-factor/) plugin is active: users without it are sent to their profile until it is set up. Nothing happens while the plugin is inactive (e.g. locally). |
| Security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and HSTS in production over HTTPS. The WordPress version is hidden. |
| Notifications | Email to the admin when a user is created or becomes administrator/editor. |

User-facing messages (login errors, lockout, emails) are in Swedish.

---

## Installation (Bedrock)

Add the repository and require an exact version in the project's `composer.json`:

```json
"repositories": [
  { "type": "vcs", "url": "https://github.com/hnrk75/wp-security-hardening" }
],
"require": {
  "hnrk75/wp-security-hardening": "1.3.2"
}
```

```bash
composer update hnrk75/wp-security-hardening
```

It is installed in `web/app/mu-plugins/wp-security-hardening/` and loaded by Bedrock's
autoloader (`roots/bedrock-autoloader`). It shows under **Plugins → Must-Use**.

Recommended together with `wpackagist-plugin/two-factor`.

---

## Releasing a new version

Tags are created automatically by a GitHub Action from the version in the plugin header.

1. Work on `dev`. Add a line under **Unreleased** in `CHANGELOG.md`.
2. Update `Version:` in the header of `wp-security-hardening.php`.
3. In `CHANGELOG.md`, rename **Unreleased** to `[x.y.z] - YYYY-MM-DD` and add a new empty **Unreleased** above it.
4. Commit on `dev` and push, then PR `dev` → `main` with **Create a merge commit**.
5. The **Tag release** action tags `vx.y.z` on `main`. Never create tags by hand — the tag must match the header.
6. On each site: change the version in `composer.json` and run `composer update hnrk75/wp-security-hardening`.

---

## License

MIT — see `LICENSE`.
