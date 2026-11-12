# php-vuln-lint

Dependency-free **static security linter for PHP** (8.1+). Sixteen rules for the classic PHP weaknesses: SQL injection, XSS, local/remote file inclusion, code and command execution, object injection, weak password hashing, variable injection, path traversal, open redirect, debug leakage, disabled TLS verification, predictable randomness, hard-coded secrets, `preg_replace /e` and unsafe uploads. Every rule carries a CWE id.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
php bin/php-vuln-lint src/                       # text report
php bin/php-vuln-lint --format=json .            # for pipelines
php bin/php-vuln-lint --fail-on=high src/        # exit code 2 at high or critical
composer test                                    # or: php tests/run.php
```

Suppress a line with `// vuln-lint:disable` or `// vuln-lint:disable PVL004,PVL009`.

## Rule set

| ID | Severity | Issue | CWE |
|----|----------|-------|-----|
| PVL001 | high | SQL from request data | 89 |
| PVL002 | high | unencoded output of request data | 79 |
| PVL003 | critical | include/require with request data | 98 |
| PVL004 | critical | eval, assert, create_function | 95 |
| PVL005 | critical | shell execution with variable data | 78 |
| PVL006 | high | unserialize without allowed_classes | 502 |
| PVL007 | medium | md5/sha1/crypt for passwords | 327 |
| PVL008 | high | extract / variable variables from input | 621 |
| PVL009 | high | file operation on a request path | 22 |
| PVL010 | medium | open redirect | 601 |
| PVL011 | medium | display_errors, phpinfo | 209 |
| PVL012 | high | TLS verification off | 295 |
| PVL013 | medium | rand, mt_rand, uniqid for secrets | 330 |
| PVL014 | high | hard-coded credential | 798 |
| PVL015 | high | preg_replace /e | 1321 |
| PVL016 | medium | upload kept under client file name | 434 |

## Limits

Line-based pattern matching, no taint tracking: it misses multi-line statements and flags some safe code. Use it as a fast first pass and complement it with Psalm taint analysis or PHPStan with security rules for deeper coverage.

## Safe by construction

The scanner never executes or includes the code it reads, skips symlinks and `vendor/`, caps file size at 1 MB, and the tests build their credential-looking fixtures at runtime.

MIT licensed.
