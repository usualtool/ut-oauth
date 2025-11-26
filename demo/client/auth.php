<?php
define('CLIENT_ID',     '应用ID');
define('CLIENT_SECRET', '应用密钥');
define('REDIRECT_URI',  '回调地址http://xxxx/client/callback');
define('OAUTH_SERVER',  '请求地址http://xxxx/server/index');
$state = bin2hex(random_bytes(16));
$_SESSION['oauth_state'] = $state;
$authUrl = OAUTH_SERVER . '&route=authorize&' . http_build_query([
    'response_type' => 'code',
    'client_id'     => CLIENT_ID,
    'redirect_uri'  => REDIRECT_URI,
    'state'         => $state,
    'scope'         => 'basic'
]);
header("Location: $authUrl");
exit;