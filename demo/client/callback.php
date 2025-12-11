<?php
define('CLIENT_ID',     '应用ID');
define('CLIENT_SECRET', '应用密钥');
define('REDIRECT_URI',  urlencode('回调地址http://xxxx/client/callback'));
define('OAUTH_SERVER',  '请求地址http://xxxx/server/index');
session_start();
if (!hash_equals($_GET['state'] ?? '', $_SESSION['oauth_state'] ?? '')) {
    die('Invalid state.');
}
if (isset($_GET['error'])) {
    die('Authorization error: ' . htmlspecialchars($_GET['error']));
}
$code = $_GET['code'] ?? '';
if (!$code) {
    die('No code received.');
}
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, OAUTH_SERVER . '&route=token');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'grant_type'    => 'authorization_code',
    'code'          => $code,
    'redirect_uri'  => REDIRECT_URI,
    'client_id'     => CLIENT_ID,
    'client_secret' => CLIENT_SECRET
]));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Content-Type: application/x-www-form-urlencoded'
]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
if ($httpCode !== 200) {
    die("Token request failed: $response");
}
$tokenData = json_decode($response, true);
$access_token = $tokenData['access_token'];
echo "<h2>授权成功</h2>";
echo "<p>Access Token: <code>" . htmlspecialchars($access_token) . "</code></p>";
