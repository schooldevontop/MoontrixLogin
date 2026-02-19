# MoontrixLogin Usage

Quick start:
1. Copy the jar to /plugins
2. Start the server to generate config.yml
3. Configure storage and security
4. Restart

Core commands:
- /register <password> [verifyPassword]
- /login <password> [totp] [remember]
- /logout
- /changepassword <oldPassword> <newPassword>
- /unregister <password>

Optional commands (disabled by default):
- /email show|add|change|recover|setpassword
- /totp add|confirm|remove|code
- /captcha <code>

Security hardening and migration details: `docs/HARDENING_GUIDE.md`
