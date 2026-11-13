<?php
/**
 * FerrousX phpMyAdmin Prefix Router (/phpadmin/, /phpmyadmin/)
 * Dùng cho: PHP_CLI_SERVER_WORKERS=4 php -S 0.0.0.0:888 -t <PMA_ROOT> pma-router.php
 * - Xử lý tiền tố /phpadmin/ và /phpmyadmin/ khi đi qua Cloudflare Proxy (cổng 80/443)
 * - Ngăn chặn Path Traversal tuyệt đối khỏi thư mục gốc phpMyAdmin
 * - Phục vụ static assets với MIME type chính xác (CSS/JS/Fonts/SVG/WOFF2)
 */

declare(strict_types=1);

$docRoot = $_SERVER['DOCUMENT_ROOT'] ?? getenv('FERROUS_PMA_ROOT') ?: __DIR__;
$realDocRoot = realpath($docRoot);
if ($realDocRoot === false) {
    http_response_code(500);
    echo 'phpMyAdmin document root not found';
    return true;
}

$rawUri = $_SERVER['REQUEST_URI'] ?? '/';
$parsedPath = parse_url($rawUri, PHP_URL_PATH);
$uriPath = is_string($parsedPath) && $parsedPath !== '' ? $parsedPath : '/';

$prefix = '';
$strippedPath = $uriPath;

if (preg_match('#^/(phpadmin|phpmyadmin)(/.*)?$#i', $uriPath, $matches)) {
    $prefix = '/' . strtolower($matches[1]);
    $strippedPath = isset($matches[2]) && $matches[2] !== '' ? $matches[2] : '/';
}

// Chuẩn hóa tránh null-byte hoặc lặp dấu gạch chéo
$strippedPath = str_replace("\0", '', $strippedPath);
if ($strippedPath === '' || $strippedPath[0] !== '/') {
    $strippedPath = '/' . $strippedPath;
}

// Chặn các đường dẫn nhạy cảm
if (preg_match('#/(libraries|templates|setup/lib|vendor|test|doc|examples|\.git)(/|$)#i', $strippedPath)) {
    if (!preg_match('#^/vendor/#i', $strippedPath) && !preg_match('#\.(css|js|svg|png|woff2?)$#i', $strippedPath)) {
        http_response_code(403);
        echo '403 Forbidden';
        return true;
    }
}

$candidate = $realDocRoot . $strippedPath;
if (is_dir($candidate)) {
    $strippedPath = rtrim($strippedPath, '/') . '/index.php';
    $candidate = $realDocRoot . $strippedPath;
}

$realTarget = realpath($candidate);
if ($realTarget === false || strpos($realTarget, $realDocRoot) !== 0 || !is_file($realTarget)) {
    // Fallback index.php nếu truy cập gốc hoặc route SPA của phpMyAdmin
    if ($strippedPath === '/' || $strippedPath === '/index.php') {
        $indexPath = realpath($realDocRoot . '/index.php');
        if ($indexPath !== false && strpos($indexPath, $realDocRoot) === 0) {
            $realTarget = $indexPath;
            $strippedPath = '/index.php';
        } else {
            http_response_code(404);
            echo '404 Not Found';
            return true;
        }
    } else {
        http_response_code(404);
        echo '404 Not Found';
        return true;
    }
}

$ext = strtolower(pathinfo($realTarget, PATHINFO_EXTENSION));

if ($ext === 'php') {
    $publicScript = ($prefix !== '' ? $prefix : '') . $strippedPath;
    $_SERVER['SCRIPT_FILENAME'] = $realTarget;
    $_SERVER['SCRIPT_NAME'] = $publicScript;
    $_SERVER['PHP_SELF'] = $publicScript;
    $_SERVER['DOCUMENT_ROOT'] = $realDocRoot;

    // Giữ nguyên thông tin HTTPS/Host từ Reverse Proxy
    if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
        $_SERVER['HTTPS'] = 'on';
    }

    chdir(dirname($realTarget));
    require $realTarget;
    return true;
}

$mimeMap = [
    'css'   => 'text/css; charset=utf-8',
    'js'    => 'application/javascript; charset=utf-8',
    'mjs'   => 'application/javascript; charset=utf-8',
    'json'  => 'application/json; charset=utf-8',
    'map'   => 'application/json; charset=utf-8',
    'html'  => 'text/html; charset=utf-8',
    'htm'   => 'text/html; charset=utf-8',
    'svg'   => 'image/svg+xml',
    'png'   => 'image/png',
    'jpg'   => 'image/jpeg',
    'jpeg'  => 'image/jpeg',
    'gif'   => 'image/gif',
    'webp'  => 'image/webp',
    'ico'   => 'image/x-icon',
    'woff'  => 'font/woff',
    'woff2' => 'font/woff2',
    'ttf'   => 'font/ttf',
    'eot'   => 'application/vnd.ms-fontobject',
    'xml'   => 'application/xml; charset=utf-8',
    'txt'   => 'text/plain; charset=utf-8',
];

$contentType = $mimeMap[$ext] ?? 'application/octet-stream';
header('Content-Type: ' . $contentType);
header('Content-Length: ' . filesize($realTarget));
header('Cache-Control: public, max-age=3600');
header('X-Content-Type-Options: nosniff');
readfile($realTarget);
return true;
