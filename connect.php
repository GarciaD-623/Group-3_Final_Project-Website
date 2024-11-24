<?php

$host = "localhost";
$user = "root";
$password = "";
$db = "user_account";
$port = "3307";

try {
	$dsn = "mysql:host=".$host.";dbname=".$db.";port=".$port;
	$conn = new PDO ( $dsn, $user, $password);
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	return $conn;
} catch (PDOException $e) {
	echo "Connection failed: ".$e->getMessage();
}

?>