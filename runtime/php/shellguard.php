<?php
/**
 * ShellGuard PHP runtime protection.
 *
 * Default behavior is MONITOR: suspicious requests are recorded as JSON lines
 * and allowed to continue. BLOCK mode is opt-in in runtime/config.json or in
 * the options passed to shellguard_protect(). This file never evaluates,
 * includes, or executes request data.
 *
 * Install with auto_prepend_file or with one require from the application
 * entrypoint. Define SHELLGUARD_NO_AUTO_INIT before requiring this file when a
 * test harness needs to call shellguard_protect() manually.
 */

declare(strict_types=1);

if (!function_exists('shellguard_protect')) {
    /** @return array<int, array<string, mixed>> */
    function shellguard_json_file(string $path, array $fallback = []): array
    {
        if (!is_file($path) || !is_readable($path)) {
            return $fallback;
        }
        $contents = @file_get_contents($path);
        if ($contents === false) {
            return $fallback;
        }
        $decoded = json_decode($contents, true);
        return is_array($decoded) ? $decoded : $fallback;
    }

    /** @param array<string, mixed> $base @param array<string, mixed> $override */
    function shellguard_merge_config(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (isset($base[$key]) && is_array($base[$key]) && is_array($value)) {
                $base[$key] = shellguard_merge_config($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }
        return $base;
    }

    function shellguard_log_regex_failure(string $context): void
    {
        error_log(
            'ShellGuard: regex match failed for ' . $context
            . ' (preg_last_error=' . (string) preg_last_error() . ').'
        );
    }

    function shellguard_preg_match(string $pattern, string $value, string $context): int
    {
        $result = @preg_match($pattern, $value);
        if ($result === false || preg_last_error() !== PREG_NO_ERROR) {
            shellguard_log_regex_failure($context);
            return 0;
        }
        return $result;
    }

    function shellguard_default_config_path(): string
    {
        if (defined('SHELLGUARD_CONFIG_PATH')) {
            return (string) constant('SHELLGUARD_CONFIG_PATH');
        }
        return __DIR__ . DIRECTORY_SEPARATOR . 'config.json';
    }

    /** @param array<string, mixed> $options @return array<string, mixed> */
    function shellguard_runtime_config(array $options = []): array
    {
        $configPath = isset($options['config_path'])
            ? (string) $options['config_path']
            : shellguard_default_config_path();
        $configPath = realpath($configPath) ?: $configPath;
        $defaults = [
            'mode' => 'monitor',
            'log_path' => '',
            'rules_path' => 'rules.json',
            'baseline_path' => '',
            'web_root' => '',
            'ip_allowlist' => [],
            'path_allowlist' => [],
            'uploads_folders' => ['upload', 'uploads', 'uploaded', 'media', 'attachments'],
            'child_process_guard' => [
                'enabled' => false,
                'mode' => 'monitor',
                'allowlist' => [],
            ],
        ];
        $config = shellguard_merge_config($defaults, shellguard_json_file($configPath, []));
        $config = shellguard_merge_config($config, $options);
        $config['_config_path'] = $configPath;
        $config['_config_dir'] = dirname($configPath);
        $config['mode'] = strtolower((string) $config['mode']) === 'block' ? 'block' : 'monitor';
        foreach (['rules_path', 'baseline_path', 'log_path'] as $pathKey) {
            if (!empty($config[$pathKey]) && !preg_match('/^(?:[A-Za-z]:[\\\\\/]|[\\\\\/])/', (string) $config[$pathKey])) {
                $config[$pathKey] = $config['_config_dir'] . DIRECTORY_SEPARATOR . $config[$pathKey];
            }
        }
        if (preg_last_error() !== PREG_NO_ERROR) {
            shellguard_log_regex_failure('runtime configuration path');
        }
        if (empty($config['web_root'])) {
            $config['web_root'] = isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] !== ''
                ? (string) $_SERVER['DOCUMENT_ROOT']
                : getcwd();
        } elseif (!preg_match('/^(?:[A-Za-z]:[\\\\\/]|[\\\\\/])/', (string) $config['web_root'])) {
            $config['web_root'] = $config['_config_dir'] . DIRECTORY_SEPARATOR . $config['web_root'];
        }
        if (preg_last_error() !== PREG_NO_ERROR) {
            shellguard_log_regex_failure('web root configuration path');
        }
        shellguard_warn_broad_allowlists($config);
        return $config;
    }

    /** @param array<string, mixed> $config @return array<string, mixed> */
    function shellguard_runtime_rules(array $config): array
    {
        $rulesPath = isset($config['rules_path']) ? (string) $config['rules_path'] : '';
        $rules = shellguard_json_file($rulesPath, []);
        return isset($rules['request_patterns']) && is_array($rules['request_patterns'])
            ? $rules
            : ['request_patterns' => []];
    }

    function shellguard_log_path(array $config): string
    {
        if (!empty($config['log_path'])) {
            return (string) $config['log_path'];
        }
        $configPath = (string) ($config['_config_path'] ?? 'shellguard');
        $processId = function_exists('getmypid') ? (string) getmypid() : 'unknown';
        $suffix = substr(hash('sha256', $configPath . '|' . $processId), 0, 16);
        return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . 'shellguard-' . $processId . '-' . $suffix
            . DIRECTORY_SEPARATOR . 'runtime.jsonl';
    }

    /** @param array<string, mixed> $config */
    function shellguard_warn_broad_allowlists(array $config): void
    {
        foreach ((array) ($config['ip_allowlist'] ?? []) as $allowed) {
            if ((string) $allowed === '*') {
                error_log('ShellGuard warning: ip_allowlist contains "*" and bypasses request inspection for every client.');
            }
        }
        foreach ((array) ($config['path_allowlist'] ?? []) as $allowed) {
            if ((string) $allowed === '/*') {
                error_log('ShellGuard warning: path_allowlist contains "/*" and bypasses request inspection for every path.');
            }
        }
    }

    /** @param array<string, mixed> $event */
    function shellguard_log(array $config, array $event): void
    {
        $event['timestamp'] = gmdate('c');
        $event['runtime'] = 'php';
        $line = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($line === false) {
            error_log('ShellGuard: could not encode a runtime log event as JSON.');
            return;
        }
        $logPath = shellguard_log_path($config);
        $directory = dirname($logPath);
        $defaultLog = empty($config['log_path']);
        if (!is_dir($directory)) {
            $directoryMode = $defaultLog ? 0700 : 0770;
            if (!@mkdir($directory, $directoryMode, true) && !is_dir($directory)) {
                error_log('ShellGuard: could not create runtime log directory: ' . $directory);
                return;
            }
        }
        if ($defaultLog && defined('PHP_OS_FAMILY') && PHP_OS_FAMILY !== 'Windows') {
            @chmod($directory, 0700);
        }
        if (!is_writable($directory)) {
            error_log('ShellGuard: runtime log directory is not writable: ' . $directory);
            return;
        }
        // Logging failures must never turn monitor mode into a site outage, but
        // they must remain visible to the server's error log.
        $written = @file_put_contents($logPath, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
        if ($written === false) {
            error_log('ShellGuard: could not write runtime JSONL log: ' . $logPath);
            return;
        }
        if (defined('PHP_OS_FAMILY') && PHP_OS_FAMILY !== 'Windows') {
            @chmod($logPath, 0600);
        }
    }

    function shellguard_request_path(): string
    {
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
        $path = parse_url($uri, PHP_URL_PATH);
        return is_string($path) && $path !== '' ? $path : '/';
    }

    function shellguard_client_ip(): string
    {
        return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : 'unknown';
    }

    /** @param mixed $value @param array<int, array{key: string, value: string}> $items */
    function shellguard_collect_values($value, string $key, array &$items, int $depth = 0): void
    {
        if ($depth > 8) {
            return;
        }
        if (is_array($value)) {
            foreach ($value as $childKey => $childValue) {
                shellguard_collect_values($childValue, $key . '.' . (string) $childKey, $items, $depth + 1);
            }
            return;
        }
        if (is_scalar($value)) {
            $items[] = ['key' => $key, 'value' => (string) $value];
        }
    }

    /** @return array<int, array{key: string, value: string}> */
    function shellguard_request_values(): array
    {
        $items = [];
        foreach (['GET' => $_GET, 'POST' => $_POST, 'COOKIE' => $_COOKIE] as $source => $values) {
            shellguard_collect_values($values, strtolower($source), $items);
        }
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            if (is_array($headers)) {
                shellguard_collect_values($headers, 'header', $items);
            }
        }
        foreach ($_SERVER as $key => $value) {
            if (strpos((string) $key, 'HTTP_') === 0 || in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true)) {
                shellguard_collect_values($value, 'server.' . strtolower((string) $key), $items);
            }
        }
        return $items;
    }

    function shellguard_parameter_name(string $key): string
    {
        $parts = explode('.', $key);
        return strtolower((string) end($parts));
    }

    function shellguard_regex_matches(string $pattern, string $value): bool
    {
        if ($pattern === '') {
            return false;
        }
        return shellguard_preg_match('~' . $pattern . '~i', $value, 'runtime request rule') === 1;
    }

    /** @param array<string, mixed> $config */
    function shellguard_ip_allowed(string $ip, array $config): bool
    {
        foreach ((array) ($config['ip_allowlist'] ?? []) as $allowed) {
            $allowed = (string) $allowed;
            if ($allowed === '*' || $allowed === $ip) {
                return true;
            }
            if (strpos($allowed, '/') !== false && function_exists('inet_pton')) {
                [$network, $bits] = array_pad(explode('/', $allowed, 2), 2, '');
                $address = @inet_pton($ip);
                $networkAddress = @inet_pton($network);
                if ($address !== false && $networkAddress !== false && is_numeric($bits)) {
                    $bytes = (int) floor(((int) $bits) / 8);
                    $remainder = ((int) $bits) % 8;
                    if (substr($address, 0, $bytes) === substr($networkAddress, 0, $bytes)) {
                        if ($remainder === 0 || (ord($address[$bytes]) & (0xFF << (8 - $remainder))) === (ord($networkAddress[$bytes]) & (0xFF << (8 - $remainder)))) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    function shellguard_path_allowed(string $path, array $config): bool
    {
        $normalized = '/' . ltrim(str_replace('\\', '/', $path), '/');
        foreach ((array) ($config['path_allowlist'] ?? []) as $allowed) {
            $allowed = '/' . ltrim(str_replace('\\', '/', (string) $allowed), '/');
            if ($allowed === '/*' || $allowed === $normalized) {
                return true;
            }
            if (substr($allowed, -1) === '*' && strpos($normalized, substr($allowed, 0, -1)) === 0) {
                return true;
            }
        }
        return false;
    }

    function shellguard_uploads_path(string $path, array $config): bool
    {
        $parts = explode('/', strtolower(trim($path, '/')));
        $folders = array_map('strtolower', (array) ($config['uploads_folders'] ?? []));
        foreach ($parts as $part) {
            if (in_array($part, $folders, true) || strpos($part, 'upload') === 0) {
                return true;
            }
        }
        return false;
    }

    function shellguard_script_path(string $path): bool
    {
        return shellguard_preg_match(
            '/\.(?:php|phtml|php5|phar|js|mjs|cjs)$/i',
            $path,
            'script path check'
        ) === 1;
    }

    function shellguard_php_execution_path(string $path): bool
    {
        return shellguard_preg_match(
            '/\.(?:php|phtml|php5|phar)$/i',
            $path,
            'PHP execution path check'
        ) === 1;
    }

    /** @param array<string, mixed> $config */
    function shellguard_baseline_new_file(string $path, array $config): bool
    {
        $baselinePath = (string) ($config['baseline_path'] ?? '');
        $webRoot = realpath((string) ($config['web_root'] ?? ''));
        if ($baselinePath === '' || $webRoot === false) {
            return false;
        }
        $requested = rawurldecode(parse_url($path, PHP_URL_PATH) ?: '/');
        if (strpos($requested, "\0") !== false || strpos($requested, '..') !== false) {
            return false;
        }
        $candidate = realpath($webRoot . DIRECTORY_SEPARATOR . ltrim($requested, '/\\'));
        if ($candidate === false || !is_file($candidate)) {
            return false;
        }
        $prefix = rtrim($webRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (strpos($candidate, $prefix) !== 0) {
            return false;
        }
        $relative = str_replace('\\', '/', substr($candidate, strlen($prefix)));
        $baseline = shellguard_json_file($baselinePath, []);
        foreach ((array) ($baseline['files'] ?? []) as $record) {
            if (is_array($record) && isset($record['path']) && (string) $record['path'] === $relative) {
                return false;
            }
        }
        return true;
    }

    /** @param array<string, mixed> $config @param array<string, mixed> $rule */
    function shellguard_rule_event(array $config, array $rule, string $path, string $parameter): array
    {
        return [
            'type' => 'request_pattern',
            'rule_id' => (string) ($rule['id'] ?? 'unknown'),
            'severity' => (string) ($rule['severity'] ?? 'medium'),
            'explanation' => (string) ($rule['description'] ?? 'Shared runtime request rule matched.'),
            'path' => $path,
            'parameter' => $parameter,
            'ip' => shellguard_client_ip(),
            'mode' => $config['mode'],
        ];
    }

    /** @param array<string, mixed> $config @return array<int, array<string, mixed>> */
    function shellguard_inspect_request(array $config): array
    {
        $path = shellguard_request_path();
        if (shellguard_ip_allowed(shellguard_client_ip(), $config) || shellguard_path_allowed($path, $config)) {
            return [];
        }
        $events = [];
        foreach ((array) shellguard_runtime_rules($config)['request_patterns'] as $rule) {
            if (!is_array($rule)) {
                continue;
            }
            foreach (shellguard_request_values() as $item) {
                $parameter = shellguard_parameter_name($item['key']);
                $parameterMatches = !isset($rule['parameter_regex'])
                    || shellguard_regex_matches((string) $rule['parameter_regex'], $parameter);
                if ($parameterMatches && shellguard_regex_matches((string) ($rule['regex'] ?? ''), $item['value'])) {
                    $events[] = shellguard_rule_event($config, $rule, $path, $item['key']);
                    break;
                }
            }
        }
        if (shellguard_uploads_path($path, $config) && shellguard_php_execution_path($path)) {
            $events[] = [
                'type' => 'uploads_execution',
                'rule_id' => 'RUNTIME-UPLOADS-PHP',
                'severity' => 'high',
                'explanation' => 'A PHP execution request targeted an uploads-style path.',
                'path' => $path,
                'ip' => shellguard_client_ip(),
                'mode' => $config['mode'],
            ];
        }
        if (shellguard_baseline_new_file($path, $config)) {
            $events[] = [
                'type' => 'baseline_new_file',
                'rule_id' => 'RUNTIME-BASELINE-NEW',
                'severity' => shellguard_script_path($path) || shellguard_uploads_path($path, $config) ? 'high' : 'low',
                'explanation' => 'The requested file is not present in the configured baseline.',
                'path' => $path,
                'ip' => shellguard_client_ip(),
                'mode' => $config['mode'],
            ];
        }
        return $events;
    }

    /** @param array<string, mixed> $event */
    function shellguard_block(array $event): void
    {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
        }
        echo "Request blocked by ShellGuard.\n";
        exit;
    }

    /** @param array<string, mixed> $options @return array<int, array<string, mixed>> */
    function shellguard_protect(array $options = []): array
    {
        $config = shellguard_runtime_config($options);
        $events = shellguard_inspect_request($config);
        foreach ($events as $event) {
            shellguard_log($config, $event);
        }
        if ($events !== [] && $config['mode'] === 'block') {
            shellguard_block($events[0]);
        }
        return $events;
    }

    /** @return array<string, string> */
    function shellguard_hardening_snippets(): array
    {
        return [
            'php_ini' => "disable_functions = exec,system,shell_exec,passthru,proc_open,popen",
            'apache_htaccess' => "<FilesMatch \"\\.(?i:php|phtml|php5|phar)$\">\n    Require all denied\n</FilesMatch>",
            'nginx' => "location ~* ^/(?:upload|uploads|uploaded|media|attachments)/.*\\.(?:php|phtml|php5|phar)$ {\n    deny all;\n}",
        ];
    }
}

if (!defined('SHELLGUARD_NO_AUTO_INIT') || !constant('SHELLGUARD_NO_AUTO_INIT')) {
    shellguard_protect();
}
