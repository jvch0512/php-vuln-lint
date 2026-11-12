<?php
declare(strict_types=1);

namespace PhpVulnLint;

final class Rule
{
    public function __construct(
        public readonly string $id,
        public readonly string $severity,
        public readonly string $cwe,
        public readonly string $pattern,
        public readonly string $message,
    ) {
    }
}
