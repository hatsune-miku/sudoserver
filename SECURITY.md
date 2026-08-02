# Security Policy

SudoServer intentionally brokers unrestricted local administrator/root execution. Do not expose its HTTP port beyond loopback and do not include JWTs, handles, Master Passwords, TOTP values, configuration files, or `seal.key` in issue reports.

Report suspected vulnerabilities privately through the repository's GitHub Security Advisory page. Include a minimal reproduction with synthetic credentials. Never test against a machine or account you do not own or have explicit permission to administer.
