![Build](https://img.shields.io/github/actions/workflow/status/schooldevontop/MoontrixLogin/build.yml)
![License](https://img.shields.io/github/license/schooldevontop/MoontrixLogin)
![Version](https://img.shields.io/github/v/release/schooldevontop/MoontrixLogin)
![Spigot](https://img.shields.io/badge/Spigot-1.21.x-orange)
![MoontrixLogin Banner](assets/banner.png)
# MoontrixLogin

Secure authentication plugin for Bukkit-based servers (Spigot/Paper/Purpur/Folia 1.21.x).

## Features
- Register / login system with BCrypt password hashing
- Session tracking with IP/UUID validation
- Anti-bot and brute-force protection
- MySQL and SQLite support
- Email verification and password recovery
- Optional TOTP (2FA) and captcha checks
- Fully configurable messages and rules

## Requirements
- Java 21+
- Spigot/Paper/Purpur/Folia 1.21.x

## Quick Start
Drop the jar into `plugins/`, start the server, then edit `plugins/MoontrixLogin/config.yml` if needed.

## Installation
1. Build or download the latest jar.
2. Place `MoontrixLogin-1.0.0.jar` into `plugins/`.
3. Start the server to generate default files.
4. Edit `plugins/MoontrixLogin/config.yml` and restart.

## Configuration
Main config: `plugins/MoontrixLogin/config.yml`  
Messages: `plugins/MoontrixLogin/messages/`  
Email templates: `plugins/MoontrixLogin/templates/`

## Commands
| Command | Description |
|---|---|
| `/register <password> <verifyPassword>` | Register a new account |
| `/login <password> [totp]` | Log in to your account |
| `/logout` | Log out of your session |
| `/changepassword <oldPassword> <newPassword>` | Change your password |
| `/unregister <password>` | Delete your account |
| `/email show\|add\|change\|recover\|setpassword` | Manage email and recover password |
| `/verification <code>` | Verify email by code |
| `/totp add\|confirm\|remove\|code` | Manage TOTP (2FA) |
| `/captcha <code>` | Complete captcha if required |
| `/moontrixlogin` | Core command (aliases: `/moontrix`, `/mlogin`) |

## Permissions
| Permission | Default | Description |
|---|---|---|
| `moontrixlogin.player.login` | true | Log in |
| `moontrixlogin.player.register` | true | Register |
| `moontrixlogin.player.logout` | true | Log out |
| `moontrixlogin.player.changepassword` | true | Change password |
| `moontrixlogin.player.unregister` | true | Unregister |
| `moontrixlogin.player.email.add` | true | Add email |
| `moontrixlogin.player.email.change` | true | Change email |
| `moontrixlogin.player.email.recover` | true | Recover by email |
| `moontrixlogin.player.email.see` | true | View email |
| `moontrixlogin.player.security.verificationcode` | true | Verify email |
| `moontrixlogin.player.totpadd` | true | Enable TOTP |
| `moontrixlogin.player.totpremove` | true | Disable TOTP |
| `moontrixlogin.player.captcha` | true | Complete captcha |

## Build (Local)
```bash
mvnw.cmd -q -DskipTests package
```

## CI / Release
GitHub Actions workflows are included:
- CI on push/PR to `main`
- Release on tags `v*` (uploads jar to GitHub Release)

## License
MIT. See `LICENSE`.
