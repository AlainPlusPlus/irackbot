# Broad security audit

Scope: public `AlainPlusPlus/irackbot` at commit `b1efb51335f87ad5c45ac05d1088ad0705a03641`, Java/Maven, Docker, and repository configuration.

## High

### 1. Unauthenticated administration transition may be exploitable

- `SlackBot.java:30` compares the sender only to `slackModeAdmin`.
- It uses substring matching (`contains("change_mode")`) and an exact username check.
- Slack display/usernames can be inconsistent across API versions and the bot does not verify channel identity or workspace.

**Impact:** If the configured admin username is predictable or shared, an attacker could attempt mode changes.

**Remediation:** Authorize by immutable Slack user ID, restrict the listener to `SLACK_CHANNEL_OBJECT`, and exact-match commands. Do not rely solely on usernames.

### 2. Slack credentials can leak through configuration or process runtime

- `config-test.properties` contains a Slack token field, but a real `config.properties` is intentionally generated locally.
- The README explicitly allows committing token-containing configuration via Heroku (`git add -A`), and `BotConstants.java` reads the token as a plain string.

**Impact:** Repository or image credential disclosure; Slack account/bot compromise.

**Remediation:** Never commit `config.properties`, enforce secret scanning, use environment variables, and rotate any token ever committed or used in deployed images.

### 3. Dangerously outdated dependencies

- JUnit `3.8.1`
- PircBot `1.5.0`
- simple-slack-api `0.6.0`
- JitPack dependencies are resolved at build time from mutable external artifacts.
- JitPack also receives no checksum/pinning guarantee in `pom.xml`.

**Impact:** Known or unpatched vulnerabilities, supply-chain risks, and TLS/runtime incompatibilities.

**Remediation:** Update dependencies and Java runtime, pin artifact/JitPack revisions, enable dependency scanning, and generate a dependency lock/SBOM.

## Medium

### 4. Plaintext IRC transport

- `IRCBot.java:13-29` connects to an IRC server using PircBot's non-TLS API.

**Impact:** Messages and IRC credentials, if used, can be exposed in transit.

**Remediation:** Use IRC-over-TLS and validate server certificates. Support modern, maintained IRC libraries.

### 5. Slack relay exposes private Slack content into a public IRC channel

- Slack messages are forwarded verbatim to IRC in `RelayMessage.java:11`.

**Impact:** Accidental disclosure of internal Slack discussions, secrets, tokens, and usernames.

**Remediation:** Clearly mark public-room behavior, restrict forwarding, and add secret redaction/content policy controls.

### 6. No command input validation

- Slack and IRC commands use broad `contains()` checks.
- IRC mentions and command names can trigger bot actions anywhere in message text.

**Impact:** Unintended command execution and bot spam.

**Remediation:** Parse commands with exact boundaries and reject oversized, malformed, or unexpected messages.

### 7. Unhandled null dereferences

- `SlackBot.java:24,74`, `IRCBot.java:44`, and `SlackBot.java:59` assume channel/user lookups and Slack IDs exist.

**Impact:** Bot crashes or event listener failure under revoked credentials or renamed/deleted users.

**Remediation:** Validate lookups and handle missing entities gracefully.

### 8. Race-prone and global mutable state

- `BotConstants.MODE` changes dynamically and is shared globally.
- `SlackBot` and `IRCBot` are public static fields.

**Impact:** Inconsistent filtering and cross-thread state races.

**Remediation:** Use immutable configuration and synchronized/atomic mode state.

## Docker/build issues

### 9. Base image is obsolete

- `Dockerfile` uses `frolvlad/alpine-oraclejdk8:slim`, Oracle JDK 8 on Alpine.

**Impact:** Unsupported runtime, outdated OpenSSL/Java crypto components, and likely known CVEs.

**Remediation:** Migrate to a supported LTS JDK and a minimal pinned base image. Run as a non-root user.

### 10. Build is not reproducible or least-privilege

- Dockerfile resolves dependencies in separate unpinned Maven steps.
- It includes build dependencies in the runtime image.

**Impact:** Supply-chain drift and larger attack surface.

**Remediation:** Use multistage builds, pinned digests, dependency verification, and a final non-root runtime image.

## Low/informational

### 11. Exception handling hides startup failures

- `BotConstants.java:71-75` prints exceptions and then closes a potentially null `inputStream`, which can itself throw `NullPointerException`.
- `Main.java:35-39` has no startup validation.

**Impact:** Misconfiguration may leave static fields unset and cause confusing runtime failures.

**Remediation:** Fail fast and validate all required properties.

### 12. Logging can expose message content

- `SlackBot.java:68-70` prints every Slack word to stdout.

**Impact:** Credentials or sensitive message contents can enter container/log aggregation.

**Remediation:** Remove debug printing and implement redacted logging.

### 13. Repository security posture

- Public fork with no license, issues disabled, and no visible security policy or Dependabot configuration.

**Impact:** Lower confidence in patch handling and maintenance.

**Remediation:** Add `SECURITY.md`, enable private vulnerability reporting, and add CI with vulnerability scanning.

## Recommended priorities

1. Rotate Slack credentials and ensure none were committed.
2. Remove or isolate secret-containing configuration and Heroku instructions.
3. Restrict mode-changing authorization to immutable Slack user IDs and channel IDs.
4. Upgrade dependencies and runtime.
5. Add TLS for IRC and secret redaction.
6. Add automated dependency, secret, and container scanning.
