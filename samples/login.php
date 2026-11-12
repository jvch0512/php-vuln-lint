<?php
$user = $_POST['user'];
$res = mysqli_query($db, "SELECT * FROM users WHERE name = '" . $_POST['user'] . "'");
echo "Welcome " . $_GET['name'];
include $_GET['page'] . '.php';
system("ping " . $_GET['host']);
$obj = unserialize($_COOKIE['data']);
$hash = md5($password);
header("Location: " . $_GET['next']);
