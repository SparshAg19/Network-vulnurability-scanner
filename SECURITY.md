# Security Policy

## Authorized Use

This project is intended only for authorized security testing on systems you own or have explicit permission to assess. Do not use it against third-party networks, public targets, or production systems without written authorization.

## Secrets

Do not hardcode API keys in source files. Set the NVD key through the `NVD_API_KEY` environment variable. Generated logs and reports are ignored by Git by default because they may contain internal hostnames, service banners, and vulnerability details.

## Reporting Security Issues

If you find a vulnerability in this project, open a private advisory or contact the maintainer before publishing details. Include a short description, reproduction steps, affected files, and recommended mitigation when possible.

## Security Assumptions

- The scanner is a local CLI tool, not a hosted web application.
- Targets, service banners, and NVD API responses are treated as untrusted input.
- HTML reports are static files and include a restrictive Content Security Policy.
- Output paths are restricted to the project directory to prevent accidental arbitrary file writes.
