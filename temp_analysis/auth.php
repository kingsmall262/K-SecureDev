$user_input = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_input;
$result = mysqli_query($conn, $query);