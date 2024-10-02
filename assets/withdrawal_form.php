<?php
// Start the session
session_start();

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    // If not logged in, redirect to login page
    header("Location: index.php");
    exit();
}

// Connect to the database
include 'connect.php';

// Get the user ID from the session
$userId = $_SESSION['user_id'];

// Check if the username is set in the session
if (!isset($_SESSION['username'])) {
    // If username is not set, fetch it from the database
    $query = "SELECT username FROM users WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $stmt->bind_result($username);
    $stmt->fetch();
    $stmt->close();

    // Store the fetched username in the session
    $_SESSION['username'] = $username;
} else {
    // Get the username from the session
    $username = $_SESSION['username'];
}

// Fetch the user's balance from the funds table
$query = "SELECT balance FROM funds WHERE user_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $userId);
$stmt->execute();
$stmt->bind_result($balance);
$stmt->fetch();
$stmt->close();

// Default balance if not set
if (!$balance) {
    $balance = '0.0000';
}

// Get the current hour
$currentHour = (int)date('G'); // 'G' gives the hour in 24-hour format without leading zeros

// Determine the appropriate greeting
if ($currentHour >= 6 && $currentHour < 12) {
    $greeting = 'Good Morning';
} elseif ($currentHour >= 12 && $currentHour < 18) {
    $greeting = 'Good Afternoon';
} else {
    $greeting = 'Good Evening';
}

// Fetch the total click count and calculate the total amount earned
$amount_per_click = 4; // Amount in Ksh per click

// Fetch the total click count for the user in the last 24 hours
$query = "SELECT COUNT(*) AS daily_clicks FROM link_clicks WHERE user_id = ? AND last_click_time >= NOW() - INTERVAL 24 HOUR";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $userId);
$stmt->execute();
$stmt->bind_result($daily_clicks);
$stmt->fetch();
$stmt->close();

// Fetch the total click count for the user overall
$query = "SELECT SUM(click_count) AS total_clicks FROM link_clicks WHERE user_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();
$total_clicks = $row['total_clicks'] ?? 0;

// Calculate the total amount earned
$total_amount_earned = $total_clicks * $amount_per_click;

// Close the connection
$conn->close();
?>


<!DOCTYPE html>
<html lang="en" dir="ltr" data-startbar="light" data-bs-theme="light">
<head>
    <meta charset="utf-8" />
    <title>Gainly - Withdrawal Form</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta content="Gainly - Withdrawal Form" name="description" />
    <meta content="" name="author" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />

    <!-- App favicon -->
    <link rel="shortcut icon" href="assets/images/favicon.ico">

    <!-- App css -->
    <link href="assets/css/bootstrap.min.css" rel="stylesheet" type="text/css" />
    <link href="assets/css/icons.min.css" rel="stylesheet" type="text/css" />
    <link href="assets/css/app.min.css" rel="stylesheet" type="text/css" />
    
    <style>
        body {
            background-color: #202221;
            color: #fff;
        }
        .card {
            background-color: #2c2f34;
            border: 1px solid #22c55e;
        }
        .auth-header-box {
            background-color: #000; /* Change to black */
            color: #fff;
        }
        .alert-success {
            color: #22c55e;
            background-color: #fff;
            border-color: #22c55e;
        }
        .alert-error {
            color: #e3342f;
            background-color: #fff;
            border-color: #e3342f;
        }
    </style>
</head>
<body>
    <div class="container-xxl">
        <div class="row vh-100 d-flex justify-content-center">
            <div class="col-12 align-self-center">
                <div class="card-body">
                    <div class="row">
                        <div class="col-lg-4 mx-auto">
                            <div class="card">
                                <div class="card-body p-0 auth-header-box rounded-top">
                                    <div class="text-center p-3">
                                        <a href="index.html" class="logo logo-admin">
                                            <img src="assets/images/logo-sm.png" height="50" alt="logo" class="auth-logo">
                                        </a>
                                        <h4 class="mt-3 mb-1 fw-semibold text-white fs-18">Time to Cash Out with Gainly!</h4>
                                        <p class="text-muted fw-medium mb-0">Withdraw your earnings below.</p>
                                    </div>
                                </div>

                                <div class="card-body pt-0">
                                    <?php
                                    session_start();
                                    include 'connect.php'; // Assuming connect.php connects to the database

                                    // Initialize variables
                                    $error_message = '';
                                    $amount = 0; // Initialize amount to 0

                                    if (isset($_SESSION['user_id'])) {
                                        $user_id = $_SESSION['user_id'];

                                        // Fetch the click_count from the database for the user
                                        $stmt = $conn->prepare("SELECT click_count FROM link_clicks WHERE user_id = ?");
                                        $stmt->bind_param("i", $user_id);
                                        $stmt->execute();
                                        $stmt->bind_result($click_count);
                                        
                                        if ($stmt->fetch()) {
                                            // If a click_count was found, multiply by 4
                                            $amount = ($click_count !== null) ? $click_count * 4 : 0;
                                        }
                                        $stmt->close();
                                    } else {
                                        // Handle the case when user_id is not set
                                        $error_message = "<div class='alert alert-error'>User ID is not set. Please log in.</div>";
                                    }

                                    if (isset($_SESSION['success'])) {
                                        echo '<div class="alert alert-success">' . $_SESSION['success'] . '</div>';
                                        unset($_SESSION['success']);
                                    }
                                    if (isset($_SESSION['error'])) {
                                        echo '<div class="alert alert-error">' . $_SESSION['error'] . '</div>';
                                        unset($_SESSION['error']);
                                    }

                                    // Check if there's an error message
                                    if ($error_message) {
                                        echo $error_message;
                                    }
                                    ?>
                                    <form action="withdraw.php" method="POST">
                                        <div class="form-group mb-2">
                                            <label class="form-label" for="amount">Amount (Ksh)</label>
                                            <input type="number" class="form-control" id="amount" 
                                                   value="<?php echo number_format($total_amount_earned, 2); ?>" 
                                                   name="withdraw_amount" min="20" required readonly>
                                            <small class="form-text text-muted">Minimum withdrawal amount is Ksh 20.</small>
                                        </div>
                                        <div class="form-group mb-2">
                                            <label class="form-label" for="mobile">Mobile Number</label>
                                            <input type="text" class="form-control" id="mobile" name="mobile" required>
                                        </div>
                                        <div class="d-grid mt-3">
                                            <button class="btn btn-primary" type="submit">Withdraw</button>
                                        </div>
                                    </form>
                                </div><!--end card-body-->
                            </div><!--end card-->
                        </div><!--end col-->
                    </div><!--end row-->
                </div><!--end card-body-->
            </div><!--end col-->
        </div><!--end row-->
    </div><!-- container -->
    
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
    <script src="assets/js/bootstrap.min.js"></script>
</body>
</html>
