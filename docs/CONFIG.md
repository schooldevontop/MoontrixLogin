# MoontrixLogin Config

Key sections:
- storage: database type and connection
- security: bcrypt, session timeout, brute-force
- antiBot: delay, shadow-ban, rate limits
- mail: SMTP settings (optional)
- protection: chat/command/move rules

Notes:
- Use SQLITE for simple setups
- Use MYSQL for large servers
- Keep brute-force limits enabled
- Do not store secrets in plaintext; use ENV/AES/Vault references
- For hardening and migration examples, read `docs/HARDENING_GUIDE.md`
