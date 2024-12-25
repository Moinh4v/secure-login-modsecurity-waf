<?php
$servername = "localhost";
$username = "root";
$password = "test@123";
$dbname = "test_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$user_input = $_POST['username'];
$sql = "SELECT * FROM users WHERE username = '$user_input'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    echo "Welcome, " . $user_input;
} else {
    echo "Invalid username.";
}

$conn->close();
?>
