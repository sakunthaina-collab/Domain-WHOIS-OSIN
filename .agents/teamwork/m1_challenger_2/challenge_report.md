# Adversarial Challenge & Stress-Test Report: `email-osint`

**Agent ID**: `m1_challenger_2` (teamwork_challenger)  
**Roles**: critic, specialist  
**Target Module**: `email-osint` (`agent/skills/investigation/email-osint/run.py` & `skills/investigation/email-osint/run.py`)  
**Verdict**: **REQUEST_CHANGES**  
**Date**: 2026-11-06T10:52:00Z  

---

## 1. Executive Summary

An adversarial stress test of the `email-osint` skill was conducted across 6 core challenge vectors:
1. Malformed email strings and boundary edge cases (missing/multiple `@`, leading/trailing/consecutive dots, spaces, special chars, CRLF, TLDs).
2. Subaddressing decomposition variants (`user+tag@example.com`, `user+tag1+tag2@example.com`, `+tag@...`, `user+@...`).
3. Known disposable domains and subdomains (`tempmail.com`, `mailinator.com`, `abc.guerrillamail.com`).
4. OPSEC enforcement under invalid or falsy `passive_only` flags.
5. Gravatar profile/avatar hashing (SHA-256 and MD5) and 404/500/timeout clean handling.
6. Cryptographic evidence envelopes and schema integrity (`source`, `query`, `timestamp`, `response_sha256`).

While the skill demonstrates strong baseline mechanics (clean Gravatar hashing and 404 handling, strict OPSEC validation, proper evidence envelopes, and 15/15 unit tests passing), adversarial probes uncovered **two high-severity defects** and **one medium-severity defect** that require remediation before production approval:

- **Defect 1 (High - Evasion/False Negative)**: Failure to recognize disposable email subdomains (`abc.guerrillamail.com`). The catalog check only matches exact domain strings; subdomains are classified as `custom_unknown` and labeled as `"Custom Corporate / Self-Hosted Mail Server"`.
- **Defect 2 (High - Injection Vulnerability)**: Regex end-of-string token vulnerability. `_LOCAL_PART_REGEX` terminates with `$` instead of `\Z`. In Python `re`, `$` matches immediately before a trailing newline `\n`. As a result, emails containing CRLF/newlines before the `@` symbol (e.g. `'user\n@domain.com'`) evaluate to `valid_format: True`, creating SMTP/header injection risks.
- **Defect 3 (Medium - Specification Incomplete)**: `_DOMAIN_REGEX` permits domain labels with leading and trailing hyphens in subsequent labels and TLDs (e.g., `user@domain.-bad` or `user@domain.bad-` evaluates to `valid_format: True`), violating RFC 1035 / RFC 1123.

---

## 2. Challenge Summary

**Overall Risk Assessment**: **HIGH** (Evasion of disposable email controls and CRLF tolerance in syntax validation).

---

## 3. Detailed Challenges & Empirical Evidence

### Challenge 1 (High): Disposable Subdomain Evasion (`abc.guerrillamail.com`)

- **Assumption Challenged**: The skill assumes that disposable domains can be identified by an exact string lookup in `DISPOSABLE_DOMAINS` (`if d_lower in DISPOSABLE_DOMAINS`) combined with MX exchange pattern matching.
- **Attack Scenario**: A malicious actor or scammer registers or uses an address under an arbitrary subdomain of a disposable email provider (e.g., `user@abc.guerrillamail.com`, `user@test.tempmail.com`, `user@random.yopmail.com`). Because subdomains often lack dedicated MX records or have NXDOMAIN for MX, the DNS MX list is empty `[]`. The exact match against `DISPOSABLE_DOMAINS` fails.
- **Empirical Proof**:
  ```python
  res = run('user@abc.guerrillamail.com', passive_only=True)
  # Result:
  # is_disposable: False
  # provider_type: 'custom_unknown'
  # infrastructure: 'Custom Corporate / Self-Hosted Mail Server'
  ```
- **Blast Radius**: High. Attackers bypass disposable email filters completely. Worse, the system reports the target as a "Corporate / Self-Hosted Mail Server", misleading intelligence analysts.
- **Mitigation**:
  In `classify_provider()`, extract domain labels and check parent domain suffixes against `DISPOSABLE_DOMAINS`:
  ```python
  domain_parts = d_lower.split(".")
  is_disposable = False
  for i in range(len(domain_parts) - 1):
      candidate = ".".join(domain_parts[i:])
      if candidate in DISPOSABLE_DOMAINS:
          is_disposable = True
          break
  ```

---

### Challenge 2 (High): Regex Newline Tolerance in Local-Part (CRLF / Header Injection)

- **Assumption Challenged**: `_LOCAL_PART_REGEX` strictly enforces RFC 5322 characters up to the end of the local-part string.
- **Attack Scenario**: An input contains an embedded newline immediately preceding the `@` delimiter, such as `'user\n@domain.com'`. `normalize_email()` calls `strip()`, which only removes leading and trailing whitespace from the outer string, leaving `\n` inside the local-part. `_LOCAL_PART_REGEX` is compiled as:
  ```python
  _LOCAL_PART_REGEX = re.compile(
      r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
  )
  ```
  In Python's standard `re` module, `$` matches at the end of the string OR immediately before a trailing newline `\n`. Therefore, `_LOCAL_PART_REGEX.match("user\n")` returns a match object!
- **Empirical Proof**:
  ```python
  res = run('user\n@domain.com', passive_only=True)
  # Result:
  # valid_format: True
  # local_part: 'user\n'
  # validation: {'syntax_valid': True, ...}
  ```
- **Blast Radius**: High. Allowing `\n` or `\r\n` into validated email strings creates SMTP Header Injection / CRLF Injection vulnerabilities if passed downstream to notifications, email senders, or ticketing systems.
- **Mitigation**:
  Replace `$` with `\Z` (strictly string end) in `_LOCAL_PART_REGEX`:
  ```python
  _LOCAL_PART_REGEX = re.compile(
      r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*\Z"
  )
  ```

---

### Challenge 3 (Medium): Domain Labels with Leading / Trailing Hyphens Permitted

- **Assumption Challenged**: `_DOMAIN_REGEX` enforces RFC 1035 / RFC 1123 domain syntax rules.
- **Attack Scenario**: Domain labels cannot begin or end with a hyphen. In `_DOMAIN_REGEX`:
  ```python
  _DOMAIN_REGEX = re.compile(
      r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$"
  )
  ```
  The negative lookahead `(?!-)` and lookbehind `(?<!-)` apply only to the first label. Subsequent labels match `(\.[a-zA-Z0-9-]{1,63})+`, which accepts leading or trailing hyphens in subsequent labels and TLDs.
- **Empirical Proof**:
  ```python
  _DOMAIN_REGEX.match("domain.-bad")  # Returns Match object (True)
  _DOMAIN_REGEX.match("domain.bad-")  # Returns Match object (True)
  res = run('user@domain.-bad', passive_only=True)
  # Result: valid_format: True
  ```
- **Blast Radius**: Medium. Allows structurally invalid domains to pass syntax validation and proceed to unnecessary DNS queries.
- **Mitigation**:
  Apply negative lookarounds to all domain label segments and terminate with `\Z`:
  ```python
  _DOMAIN_REGEX = re.compile(
      r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+\Z"
  )
  ```

---

## 4. Stress Test Results Matrix

| # | Probe Scenario | Target Input | Expected Behavior | Actual Empirical Result | Status |
|---|----------------|--------------|-------------------|-------------------------|:------:|
| 1 | Missing `@` | `plainaddress` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 2 | Multiple `@` | `user@domain@another.com` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 3 | Trailing dot local | `user.@domain.com` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 4 | Leading dot local | `.user@domain.com` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 5 | Trailing dot domain | `user@domain.com.` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 6 | Leading dot domain | `user@.domain.com` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 7 | Consecutive dots | `user..name@domain.com` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 8 | Internal spaces | `user name@domain.com` | `valid_format: False` | `valid_format: False`, `ok: True` | **PASS** |
| 9 | Outer spaces | `"  user@domain.com  "` | Normalized & valid | `valid_format: True`, normalized | **PASS** |
| 10 | Non-string input | `None`, `12345` | `ok: False`, error msg | `ok: False`, error msg | **PASS** |
| 11 | Null byte injection | `'user\x00@domain.com'` | `valid_format: False` | `valid_format: False` | **PASS** |
| 12 | Newline before `@` | `'user\n@domain.com'` | `valid_format: False` | **`valid_format: True` (VULNERABILITY)** | **FAIL** |
| 13 | Hyphen TLD boundary | `user@domain.-bad` | `valid_format: False` | **`valid_format: True` (RFC defect)** | **FAIL** |
| 14 | Subaddress simple | `user+tag@example.com` | `base='user', tag='tag'` | `base='user', tag='tag'` | **PASS** |
| 15 | Subaddress multi-tag | `user+tag1+tag2@example.com` | `base='user', tag='tag1+tag2'` | `base='user', tag='tag1+tag2'` | **PASS** |
| 16 | Subaddress empty base | `+tag@example.com` | `base='', tag='tag'` | `base='', tag='tag'` | **PASS** |
| 17 | Known disposable domain | `test@tempmail.com` | `is_disposable: True` | `is_disposable: True`, type=disposable | **PASS** |
| 18 | Known disposable domain | `scam@mailinator.com` | `is_disposable: True` | `is_disposable: True`, type=disposable | **PASS** |
| 19 | Disposable subdomain | `user@abc.guerrillamail.com` | `is_disposable: True` | **`is_disposable: False`, `type=custom_unknown` (EVASION)** | **FAIL** |
| 20 | Disposable subdomain (mock MX) | `user@test.10minutemail.com` | `is_disposable: True` | **`is_disposable: False`, `type=custom_unknown` (EVASION)** | **FAIL** |
| 21 | OPSEC violation `False` | `passive_only=False` | `ValueError("OPSEC...")` | Raises `ValueError` | **PASS** |
| 22 | OPSEC falsy values | `passive_only=0, '', None` | `ValueError("OPSEC...")` | Raises `ValueError` | **PASS** |
| 23 | Gravatar SHA-256 calc | Canonical lower email | Exact SHA-256 digest | Verified match | **PASS** |
| 24 | Gravatar MD5 calc | Canonical lower email | Exact MD5 digest | Verified match | **PASS** |
| 25 | Gravatar 404 clean | 404 response | `has_gravatar: False`, no ev | `has_gravatar: False`, clean | **PASS** |
| 26 | Gravatar 500 & timeout | Error response / timeout | Clean fallback, no unhandled exc | Clean fallback, no exc | **PASS** |
| 27 | Evidence schema | All emitted claims | Has `source, query, timestamp, response_sha256` | 100% compliant, 64-char hex sha | **PASS** |

---

## 5. Unchallenged Areas

- **Live outbound SMTP VRFY/RCPT TO**: Intentionally unprobed due to OPSEC constraint R1/R4 (strictly passive reconnaissance; active SMTP probing violates passive_only).
- **Physical rate limit / IP bans on Gravatar**: Live high-volume querying against Gravatar was intentionally avoided to protect test infrastructure and respect third-party terms of service.

---

## 6. Actionable Recommendations for Worker

1. **Fix `classify_provider` for Disposable Subdomains**:
   In `agent/skills/investigation/email-osint/run.py` and mirror `skills/investigation/email-osint/run.py`:
   Update `classify_provider()` to split `d_lower` by `.` and check all parent domain suffixes against `DISPOSABLE_DOMAINS`.
2. **Fix `_LOCAL_PART_REGEX` and `_DOMAIN_REGEX`**:
   Replace `$` with `\Z` in `_LOCAL_PART_REGEX`.
   Add `(?!-)` and `(?<!-)` to label segments in `_DOMAIN_REGEX` and terminate with `\Z`.
3. **Add Regression Tests**:
   Add unit tests in `agent/tests/test_email_osint.py` verifying:
   - `abc.guerrillamail.com` and `sub.mailinator.com` are detected as disposable even when MX records are empty.
   - `user\n@domain.com` is rejected with `valid_format: False`.
   - `user@domain.-bad` is rejected with `valid_format: False`.
