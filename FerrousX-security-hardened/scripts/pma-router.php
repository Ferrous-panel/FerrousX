<?php
/**
 * FerrousX phpMyAdmin Internal Router Script (/etc/ferrousx/pma-router.php)
 * - Chỉ chấp nhận kết nối từ Loopback Reverse Proxy (127.0.0.1 / ::1)
 * - Hỗ trợ truy cập qua Cloudflare Reverse Proxy (/phpadmin/* và /phpmyadmin/*) trên cổng 80/443
 * - Chặn tuyệt đối Path Traversal, Null Byte, tệp ẩn (.env, .git, .ht*) và thư mục /setup/
 */

$remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
if ($remoteAddr !== '127.0.0.1' && $remoteAddr !== '::1') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo '403 Forbidden: Direct external access to phpMyAdmin internal port is disabled.';
    exit;
}

$docRoot = '/usr/share/phpmyadmin';
$realDocRoot = realpath($docRoot);
if ($realDocRoot === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo '500 Internal Server Error: phpMyAdmin directory not found.';
    exit;
}

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($uri) || $uri === '' || strpos($uri, "\0") !== false) {
    http_response_code(400);
    exit;
}

// Bóc tách tiền tố /phpadmin hoặc /phpmyadmin khi đi qua FerrousX Reverse Proxy
if (preg_match('#^/(phpadmin|phpmyadmin)(/.*)?$#i', $uri, $m)) {
    $uri = isset($m[2]) && $m[2] !== '' ? $m[2] : '/';
}

// Chặn truy cập thư mục cài đặt /setup/, tệp cấu hình ẩn hoặc Path Traversal
if (
    strpos($uri, '..') !== false ||
    preg_match('#^/setup(/|$)#i', $uri) ||
    preg_match('#/\.(ht|env|git)#i', $uri)
) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo '403 Forbidden';
    exit;
}

$target = $realDocRoot . $uri;
if (is_dir($target)) {
    $target = rtrim($target, '/') . '/index.php';
}

$realTarget = realpath($target);
if ($realTarget === false || strpos($realTarget, $realDocRoot) !== 0 || !is_file($realTarget)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo '404 Not Found';
    exit;
}

$ext = strtolower(pathinfo($realTarget, PATHINFO_EXTENSION));
$staticMimes = [
    'css'   => 'text/css; charset=utf-8',
    'js'    => 'application/javascript; charset=utf-8',
    'png'   => 'image/png',
    'gif'   => 'image/gif',
    'jpg'   => 'image/jpeg',
    'jpeg'  => 'image/jpeg',
    'svg'   => 'image/svg+xml',
    'ico'   => 'image/x-icon',
    'woff'  => 'font/woff',
    'woff2' => 'font/woff2',
    'ttf'   => 'font/ttf',
    'json'  => 'application/json; charset=utf-8',
];

if (isset($staticMimes[$ext])) {
    header('Content-Type: ' . $staticMimes[$ext]);
    header('X-Content-Type-Options: nosniff');
    readfile($realTarget);
    return true;
}

if ($ext === 'php') {
    chdir(dirname($realTarget));
    $_SERVER['SCRIPT_FILENAME'] = $realTarget;
    $_SERVER['SCRIPT_NAME'] = $uri;
    $_SERVER['DOCUMENT_ROOT'] = $realDocRoot;
    require $realTarget;
    return true;
}

http_response_code(403);
echo '403 Forbidden';
return true;
