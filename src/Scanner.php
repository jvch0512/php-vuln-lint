<?php
declare(strict_types=1);

namespace PhpVulnLint;

final class Scanner
{
    public const SEVERITIES = ['low', 'medium', 'high', 'critical'];
    private const MAX_BYTES = 1_000_000;

    /** @var Rule[] */
    private array $rules;

    public function __construct(?array $rules = null)
    {
        $this->rules = $rules ?? Rules::all();
    }

    /** @return array<int, array{id:string,severity:string,cwe:string,message:string,file:string,line:int,code:string}> */
    public function scanSource(string $source, string $file = '(string)'): array
    {
        $out = [];
        $inBlock = false;
        foreach (preg_split('/\R/', $source) ?: [] as $i => $line) {
            $trim = ltrim($line);
            if ($inBlock) {
                if (str_contains($line, '*/')) {
                    $inBlock = false;
                }
                continue;
            }
            if (str_starts_with($trim, '/*') && !str_contains($line, '*/')) {
                $inBlock = true;
                continue;
            }
            if ($trim === '' || str_starts_with($trim, '//') || str_starts_with($trim, '#') || str_starts_with($trim, '*') || str_starts_with($trim, '/*')) {
                continue;
            }
            $disabled = null;
            if (preg_match('/vuln-lint:disable(?:\s+(PVL\d{3}(?:\s*,\s*PVL\d{3})*))?/', $line, $m)) {
                $disabled = isset($m[1]) ? preg_split('/\s*,\s*/', $m[1]) : 'all';
            }
            foreach ($this->rules as $rule) {
                if (preg_match($rule->pattern, $line) !== 1) {
                    continue;
                }
                if ($disabled === 'all' || (is_array($disabled) && in_array($rule->id, $disabled, true))) {
                    continue;
                }
                $out[] = ['id' => $rule->id, 'severity' => $rule->severity, 'cwe' => $rule->cwe, 'message' => $rule->message,
                    'file' => $file, 'line' => $i + 1, 'code' => trim($line)];
            }
        }
        return $out;
    }

    public function scanPath(string $path): array
    {
        $files = [];
        if (is_file($path)) {
            $files[] = $path;
        } elseif (is_dir($path)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                /** @var \SplFileInfo $f */
                if ($f->isFile() && !$f->isLink() && preg_match('/\.(?:php|phtml|inc)$/i', $f->getFilename())
                    && !preg_match('#/(?:vendor|node_modules|\.git)/#', $f->getPathname())) {
                    $files[] = $f->getPathname();
                }
            }
            sort($files);
        }
        $out = [];
        foreach ($files as $f) {
            if (filesize($f) > self::MAX_BYTES) {
                continue;
            }
            array_push($out, ...$this->scanSource((string) file_get_contents($f), $f));
        }
        return $out;
    }

    public static function worstIndex(array $findings): int
    {
        $worst = -1;
        foreach ($findings as $f) {
            $worst = max($worst, (int) array_search($f['severity'], self::SEVERITIES, true));
        }
        return $worst;
    }
}
