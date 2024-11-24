<?php 
session_destroy();
setcookie('email', $email, time()-1);
setcookie('pass', $password, time()-1);
header("location: index.html");

































?>