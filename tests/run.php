<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/Rule.php';
require_once __DIR__ . '/../src/Rules.php';
require_once __DIR__ . '/../src/Scanner.php';

use PhpVulnLint\Scanner;

$failures = 0;
$count = 0;

function ids(string $code): array
{
    return array_column((new Scanner())->scanSource($code), 'id');
}

function check(string $name, bool $ok): void
{
    global $failures, $count;
    $count++;
    if (!$ok) {
        $failures++;
        echo "FAIL $name\n";
    }
}

function flags(string $rule, string $code): bool { return in_array($rule, ids($code), true); }

// SQL injection
check('sqli concat', flags('PVL001', '$r = mysqli_query($db, "SELECT * FROM t WHERE a = \'" . $_GET[\'a\'] . "\'");'));
check('sqli interpolation', flags('PVL001', '$q = "DELETE FROM t WHERE id = {$_GET[\'id\']}";'));
check('prepared statement is clean', ids('$s = $pdo->prepare("SELECT * FROM t WHERE a = ?"); $s->execute([$_GET["a"]]);') === []);
// XSS
check('xss echo', flags('PVL002', 'echo "Hi " . $_GET[\'n\'];'));
check('xss short echo tag', flags('PVL002', '<?= $_GET["n"] ?>'));
check('encoded echo is clean', !flags('PVL002', 'echo htmlspecialchars($_GET["n"], ENT_QUOTES, "UTF-8");'));
check('int cast echo is clean', !flags('PVL002', 'echo (int)$_GET["n"];'));
// inclusion, eval, exec
check('lfi', flags('PVL003', 'include $_GET["page"] . ".php";'));
check('static include is clean', !flags('PVL003', 'require_once __DIR__ . "/config.php";'));
check('eval', flags('PVL004', 'eval($code);'));
check('shell exec', flags('PVL005', 'system("ping " . $_GET["h"]);'));
check('backticks', flags('PVL005', '$o = `ls $dir`;'));
// deserialisation and crypto
check('unserialize', flags('PVL006', '$o = unserialize($_COOKIE["d"]);'));
check('unserialize allowed_classes is clean', !flags('PVL006', '$o = unserialize($s, ["allowed_classes" => false]);'));
check('md5 password', flags('PVL007', '$h = md5($password);'));
check('password_hash is clean', ids('$h = password_hash($password, PASSWORD_DEFAULT);') === []);
// variable injection, files, redirect, debug, tls, random, secrets
check('extract', flags('PVL008', 'extract($_POST);'));
check('path traversal', flags('PVL009', '$c = file_get_contents($_GET["f"]);'));
check('open redirect', flags('PVL010', 'header("Location: " . $_GET["next"]);'));
check('phpinfo', flags('PVL011', 'phpinfo();'));
check('curl verify off', flags('PVL012', 'curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);'));
check('weak random token', flags('PVL013', '$token = mt_rand();'));
check('random_bytes is clean', !flags('PVL013', '$token = bin2hex(random_bytes(16));'));
$secret = str_repeat('Ab3', 6);   // built at runtime: the repository holds no credential-like literal
check('hard-coded secret', flags('PVL014', '$api_key = "' . $secret . '";'));
check('env secret is clean', !flags('PVL014', '$api_key = getenv("API_KEY");'));
check('preg_replace /e', flags('PVL015', 'preg_replace("/x/e", $r, $s);'));
check('upload client name', flags('PVL016', 'move_uploaded_file($_FILES["f"]["tmp_name"], "up/" . $_FILES["f"]["name"]);'));
// comments and markers
check('line comment ignored', ids('// eval($x);') === []);
check('hash comment ignored', ids('# system($_GET["x"]);') === []);
check('block comment ignored', ids("/*\neval(\$x);\n*/") === []);
check('disable all', ids('eval($x); // vuln-lint:disable') === []);
check('disable specific', ids('eval($x); // vuln-lint:disable PVL004') === []);
check('wrong disable still flags', flags('PVL004', 'eval($x); // vuln-lint:disable PVL001'));
// path scanning and CLI
$dir = sys_get_temp_dir() . '/pvl_' . bin2hex(random_bytes(4));
mkdir($dir . '/vendor', 0777, true);
file_put_contents("$dir/a.php", "<?php\n\$x = 1;\neval(\$y);\n");
file_put_contents("$dir/vendor/b.php", "<?php eval(\$y);\n");
$f = (new Scanner())->scanPath($dir);
check('vendor skipped, line number right', count($f) === 1 && $f[0]['line'] === 3);
$bin = escapeshellarg(__DIR__ . '/../bin/php-vuln-lint');
exec(PHP_BINARY . " $bin --format=json " . escapeshellarg(__DIR__ . '/../samples'), $out, $code);
$json = json_decode(implode("\n", $out), true);
check('cli json on sample', $code === 2 && is_array($json) && count($json) >= 6);
file_put_contents("$dir/a.php", "<?php\n\$x = 1;\n");
exec(PHP_BINARY . " $bin " . escapeshellarg($dir), $o2, $code2);
check('cli clean exit 0', $code2 === 0);
array_map('unlink', [ "$dir/a.php", "$dir/vendor/b.php" ]);
rmdir("$dir/vendor");
rmdir($dir);

echo ($count - $failures) . "/$count checks passed\n";
exit($failures === 0 ? 0 : 1);
