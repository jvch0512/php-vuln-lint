<?php
declare(strict_types=1);

namespace PhpVulnLint;

final class Rules
{
    /** Superglobals that carry attacker-controlled data. */
    public const INPUT = '\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER\s*\[\s*[\'"](?:HTTP_|QUERY_STRING|REQUEST_URI|PHP_SELF))';

    /** @return Rule[] */
    public static function all(): array
    {
        $in = self::INPUT;
        return [
            new Rule('PVL001', 'high', 'CWE-89', "/(?:mysqli?_query|->query|->exec|pg_query)\s*\([^;]*$in|(?:SELECT|INSERT|UPDATE|DELETE)\b[^;]*\{?\\\$_(?:GET|POST|REQUEST|COOKIE)/i", 'SQL built from request data. Use prepared statements with bound parameters'),
            new Rule('PVL002', 'high', 'CWE-79', "/\\b(?:echo|print)\\b(?![^;]*(?:htmlspecialchars|htmlentities|intval|\\(int\\)|esc_))[^;]*$in|<\\?=\\s*$in/", 'Request data echoed without output encoding (XSS). Use htmlspecialchars($x, ENT_QUOTES, "UTF-8")'),
            new Rule('PVL003', 'critical', 'CWE-98', "/\b(?:include|include_once|require|require_once)\b\s*\(?[^;]*$in/", 'File inclusion from request data (LFI/RFI)'),
            new Rule('PVL004', 'critical', 'CWE-95', "/\b(?:eval|assert|create_function)\s*\(/", 'Dynamic code execution'),
            new Rule('PVL005', 'critical', 'CWE-78', "/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^;]*(?:$in|\\\$\w+)|`[^`]*\\\$\w+[^`]*`/", 'Shell command with variable data. Use escapeshellarg() or avoid the shell'),
            new Rule('PVL006', 'high', 'CWE-502', "/\bunserialize\s*\((?![^;]*allowed_classes)/", 'unserialize() without allowed_classes (object injection). Prefer json_decode'),
            new Rule('PVL007', 'medium', 'CWE-327', "/\b(?:md5|sha1)\s*\([^;]*(?:pass|pwd|secret)|\bcrypt\s*\(/i", 'Weak hashing of passwords. Use password_hash()/password_verify()'),
            new Rule('PVL008', 'high', 'CWE-621', "/\b(?:extract|parse_str)\s*\(\s*(?:$in|\\\$_)|\\\$\\\$\w+\s*=\s*$in/", 'Variable injection from request data (extract / variable variables)'),
            new Rule('PVL009', 'high', 'CWE-22', "/\b(?:file_get_contents|file_put_contents|fopen|readfile|unlink|copy|rename|file)\s*\([^;]*$in/", 'File operation on a path from request data (path traversal / SSRF)'),
            new Rule('PVL010', 'medium', 'CWE-601', "/\bheader\s*\(\s*['\"]Location:[^;]*$in/i", 'Open redirect: Location header from request data'),
            new Rule('PVL011', 'medium', 'CWE-209', "/ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*(?:['\"]?(?:1|on|true)['\"]?)|\bphpinfo\s*\(|\berror_reporting\s*\(\s*E_ALL\s*\)[^;]*;\s*\/\/\s*prod/i", 'Debug output exposed (display_errors / phpinfo)'),
            new Rule('PVL012', 'high', 'CWE-295', "/CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)|'verify'\s*=>\s*false|verify_peer['\"]?\s*=>\s*false/i", 'TLS certificate verification disabled'),
            new Rule('PVL013', 'medium', 'CWE-330', "/(?:token|secret|nonce|otp|session|key|password)\w*\s*=.*\b(?:rand|mt_rand|uniqid|lcg_value)\s*\(/i", 'Predictable randomness for a security value. Use random_bytes() / random_int()'),
            new Rule('PVL014', 'high', 'CWE-798', "/(?:password|passwd|secret|api_?key|token)\w*['\"]?\s*(?:=>|=)\s*['\"][A-Za-z0-9+\/=_\-]{12,}['\"]/i", 'Hard-coded credential. Load it from the environment'),
            new Rule('PVL015', 'high', 'CWE-1321', "/preg_replace\s*\(\s*['\"].*\/[a-z]*e[a-z]*['\"]/", 'preg_replace with the /e modifier executes code (removed in PHP 7)'),
            new Rule('PVL016', 'medium', 'CWE-434', "/move_uploaded_file\s*\([^;]*\\\$_FILES\s*\[[^\]]*\]\s*\[\s*['\"]name['\"]/", 'Upload stored under the client-supplied file name (path traversal, executable upload)'),
        ];
    }
}
