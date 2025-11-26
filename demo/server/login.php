<?php
//登录逻辑主要获取$_SESSION['uid']
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $_SESSION['uid'] = 1;
}
?>
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h2>登录账号</h2>
<?php if (!empty($error)): ?>
    <p style="color:red"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>
<form method="post">
    账户: <input name="username" required><br><br>
    密码: <input name="password" type="password" required><br><br>
    <button type="submit">登录</button>
</form>
</body>
</html>