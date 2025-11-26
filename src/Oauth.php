<?php
namespace usualtool\Oauth;
use OAuth2;
use OAuth2\Request;
use OAuth2\Response;
use library\UsualToolInc\UTInc;
class Oauth{
    private $server;
    public function __construct(){
        $config = UTInc::GetConfig();
        $storage = new OAuth2\Storage\Pdo([
            "dsn"      => "mysql:dbname=" . $config["MYSQL_DB"] . ";host=" . $config["MYSQL_HOST"],
            "username" => $config["MYSQL_USER"],
            "password" => $config["MYSQL_PASS"]
        ]);
        $this->server = new OAuth2\Server($storage);
        $this->server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage, [
            'access_lifetime'         => 1800,
            'refresh_token_lifetime'  => 1209600,
            'always_issue_new_refresh_token' => true
        ]));
        $this->server->addGrantType(new OAuth2\GrantType\ClientCredentials($storage, [
            'access_lifetime' => 3600
        ]));
    }
    /**
     * Token 端点：处理 token
     */
    public function Token(){
    $request = Request::createFromGlobals();
    $response = new Response();

    $this->server->handleTokenRequest($request, $response);
    $response->send();
    }
    /**
     * 验证访问令牌（用于 API 保护）
     */
    public function Validate(){
        $request = Request::createFromGlobals();
        if (!$this->server->verifyResourceRequest($request)) {
            $this->server->getResponse()->send();
            die;
        }
        return $this->server->getAccessTokenData($request);
    }
    /**
     * 获取当前已登录用户 ID（通过 session）
     * @return string|null
     */
    private function GetCurrentUid(): ?string{
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        return $_SESSION['oauth_uid'] ?? null;
    }
    /**
     * 重定向到登录页，并携带返回地址
     */
    private function RequireLogin(string $currentUrl): void{
        $_SESSION['oauth_original_request'] = $_GET;
        $loginUrl = '/?m=ut-oauth&p=login&redirect=' . urlencode($currentUrl);
        header("Location: $loginUrl");
        exit;
    }
    /**
     * 授权端点：处理 authorize
     */
    public function Authorize(): void{
        if(isset($_GET['redirect_uri'])) {
            $_GET['redirect_uri'] = urldecode($_GET['redirect_uri']);
        }
        $request = Request::createFromGlobals();
        $response = new Response();
        if(!$this->server->validateAuthorizeRequest($request, $response)) {
            $response->send();
            return;
        }
        $uid = $this->GetCurrentUid();
        if(!$uid) {
            $currentUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                        . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
            $this->RequireLogin($currentUrl);
            return;
        }
        if(empty($_POST)) {
            $client_id = $_GET['client_id'] ?? '未知';
echo <<<HTML
    <!DOCTYPE html>
    <html>
    <head><title>授权访问</title></head>
    <body>
        <h2>授权申请</h2>
        <p>用户ID: <strong>{$uid}</strong></p>
        <p>应用ID: <code>{$client_id}</code></p>
        <p>您是否授予此应用程序访问您帐户的权限？</p>
        <form method="post">
            <input type="hidden" name="uid" value="{$uid}">
            <button type="submit" name="authorized" value="yes">允许</button>
            <button type="submit" name="authorized" value="no">拒绝</button>
        </form>
        </body>
    </html>
HTML;
            return;
        }
        $postUserId = $_POST['uid'] ?? null;
        $isAuthorized = ($_POST['authorized'] ?? 'no') === 'yes';
        if(!$postUserId || !hash_equals($postUserId, $uid)) {
            http_response_code(400);
            exit('授权ID不匹配');
        }
        $this->server->handleAuthorizeRequest($request, $response, $isAuthorized, $postUserId);
        $response->send();
    }
}
