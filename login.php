<?php 
include 'connect.php';


	if (isset($_POST['signUp'])) {

    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = password_hash(trim($_POST['password']), PASSWORD_DEFAULT);

 
    $query = "SELECT * FROM users WHERE email = :email";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
     
        echo "This email is already registered. Please choose another email.";
    } else {
        
        $query = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $password);

        if ($stmt->execute()) {
          header("Location: index.html");
        } else {
            echo "There was an error registering the user.";
        }
    }
}

if (isset($_POST['signIn'])) 
{
    
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    
    $query = "SELECT * FROM users WHERE email = :email";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($stmt->rowCount() > 0) 
   {
   
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC))  

	 if(isset($_POST['remember']))
     {
		setcookie('email', $email, time()+60*60*7);
		setcookie('pass', $password, time()+60*60*7);
     }
         session_start(); 
		$_SESSION['email']=$row['email'];
		header("Location: homepage.php");
    
   }

}      
   else {
            echo "Not found, incorrect email or password.";
        }