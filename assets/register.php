<?php
error_reporting(E_ALL);
ini_set('display_errors', 1); // Enable PHP error display for debugging

include 'connect.php'; // Ensure this contains your database connection code

session_start();

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php'; // Include Composer's autoloader

// Function to display styled success or error messages with a card look
function displayMessage($message, $type = 'success', $resendButton = false) {
    $backgroundColor = $type === 'error' ? '#f8d7da' : '#22c55e'; // Red for error, green for success
    $textColor = $type === 'error' ? '#721c24' : '#ffffff'; // Dark red for error text, white for success text

    $resendButtonHtml = '';
    if ($resendButton) {
        $resendButtonHtml = '
        <form method="post" style="margin-top: 20px;">
            <input type="hidden" name="resend_email" value="1">
            <button type="submit" style="background-color: #22c55e; color: #ffffff; padding: 10px 20px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer;">
                Resend Verification Email
            </button>
        </form>';
    }

    echo '
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #202221;
            color: #ffffff;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .message-container {
            max-width: 600px;
            background-color: #202221; /* Changed from white to dark */
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            padding: 20px;
            text-align: center;
        }
        .message-header {
            background-color: #202221;
            padding: 15px 0;
            color: #ffffff;
        }
        .message-body {
            padding: 20px;
            background-color: ' . $backgroundColor . ';
            color: ' . $textColor . ';
            border-radius: 8px;
            font-size: 16px;
        }
    </style>
    <div class="message-container">
        <div class="message-header">
            <h1>Gainly</h1>
        </div>
        <div class="message-body">
            ' . htmlspecialchars($message) . '
            ' . $resendButtonHtml . '
        </div>
    </div>';
}

function sendVerificationEmail($email, $username, $verificationToken) {
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'mutitupeter76@gmail.com'; // Your email address
        $mail->Password   = 'fbwj edrn alpz alur'; // Your app password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        // Recipients
        $mail->setFrom('mutitupeter76@gmail.com', 'Gainly');
        $mail->addAddress($email); // Send to the user's email

        // Email content
        $mail->isHTML(true);
        $mail->Subject = 'Email Verification';

        // Email body with professional design and white background
        $mail->Body = '
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                    background-color: #ffffff;
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    color: #333333;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }
                .email-container {
                    max-width: 600px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    padding: 20px;
                    text-align: center;
                }
                .email-header {
                    background-color: #202221;
                    padding: 15px 0;
                    color: #ffffff;
                }
                .email-body h2 {
                    margin-bottom: 10px;
                    color: #202221;
                }
                .verify-button {
                    background-color: #22c55e;
                    color: #ffffff;
                    text-decoration: none;
                    padding: 12px 25px;
                    font-size: 16px;
                    border-radius: 4px;
                    display: inline-block;
                    margin-top: 20px;
                }
                .verify-button:hover {
                    background-color: #1ba34c;
                }
                .email-footer {
                    margin-top: 30px;
                    font-size: 12px;
                    color: #666666;
                }
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="email-header">
                    <h1>Gainly</h1>
                </div>
                <div class="email-body">
                    <h2>Thank You for Registering!</h2>
                    <p>Dear ' . htmlspecialchars($username) . ',</p>
                    <p>We are excited to have you with us at Gainly. Please click the button below to verify your email and complete your registration.</p>
                    <a href="https://gainly.000.pe/verify.php?token=<?php echo $verificationToken; ?>" class="verify-button">Verify Email</a>
                    
                </div>
                <div class="email-footer">
                    <p>If you didn\'t sign up for this account, please ignore this email.</p>
                </div>
            </div>
        </body>
        </html>';

        $mail->send();
        return true;
    } catch (Exception $e) {
        return $mail->ErrorInfo;
    }
}

function logFailedEmail($email, $username, $verificationToken) {
    global $conn;
    $stmt = $conn->prepare("INSERT INTO failed_emails (email, username, token) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $email, $username, $verificationToken);
    $stmt->execute();
    $stmt->close();
}

function resendFailedEmail() {
    global $conn;
    $stmt = $conn->prepare("SELECT email, username, token FROM failed_emails ORDER BY last_attempt DESC LIMIT 1");
    $stmt->execute();
    $stmt->bind_result($email, $username, $verificationToken);
    $stmt->fetch();
    $stmt->close();

    if ($email && $username && $verificationToken) {
        $error = sendVerificationEmail($email, $username, $verificationToken);
        if ($error === true) {
            $stmt = $conn->prepare("UPDATE failed_emails SET is_sent = 1 WHERE email = ? AND token = ?");
            $stmt->bind_param("ss", $email, $verificationToken);
            $stmt->execute();
            $stmt->close();
            return "A new verification email has been sent. Please check your inbox.";
        } else {
            return "Email could not be sent again. Mailer Error: {$error}";
        }
    } else {
        return "No failed email records found.";
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['register'])) {
        // Registration
        $username = $_POST['username'];
        $email = $_POST['useremail'];
        $password = $_POST['password'];
        $confirmpassword = $_POST['confirmpassword'];
        $mobilenumber = $_POST['mobilenumber'];

        // Check if passwords match
        if ($password !== $confirmpassword) {
            displayMessage("Passwords do not match.", 'error');
            exit();
        }

        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        // Check if email already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            displayMessage("Email already registered.", 'error');
            exit();
        }

        $stmt->close();

        // Generate a unique verification token
        $verificationToken = bin2hex(random_bytes(16));

        // Insert user details into the database
        $stmt = $conn->prepare("INSERT INTO users (username, email, password, mobilenumber, token, is_verified) VALUES (?, ?, ?, ?, ?, 0)");
        $stmt->bind_param("sssss", $username, $email, $hashedPassword, $mobilenumber, $verificationToken);

        if ($stmt->execute()) {
            // Attempt to send verification email
            $error = sendVerificationEmail($email, $username, $verificationToken);
            if ($error === true) {
                displayMessage("A verification email has been sent to your email address. Please check your inbox to verify your account.");
            } else {
                // Log the failed attempt and show error message
                logFailedEmail($email, $username, $verificationToken);
                displayMessage("Email could not be sent. Mailer Error: {$error}", 'error', true);
            }
        } else {
            displayMessage("Error: " . $stmt->error, 'error');
        }

        $stmt->close();
    } elseif (isset($_POST['login'])) {
        // Login logic
        $email = $_POST['email'];
        $password = $_POST['password'];

        if (empty($email) || empty($password)) {
            displayMessage("Please fill in all fields.", 'error');
            exit();
        }

        // Check if user exists
        $stmt = $conn->prepare("SELECT id, password, is_verified FROM users WHERE email = ?");
        if (!$stmt) {
            displayMessage("Prepare statement failed: " . $conn->error, 'error');
            exit();
        }

        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $hashedPassword, $isVerified);
            $stmt->fetch();

            // Verify password
            if (password_verify($password, $hashedPassword)) {
                if ($isVerified) {
                    $_SESSION['user_id'] = $id;
                    header("Location: dashboard.php");
                    exit();
                } else {
                    displayMessage("Your email address is not verified. Please check your email to verify your account.", 'error');
                }
            } else {
                displayMessage("Incorrect password.", 'error');
            }
        } else {
            displayMessage("No account found with that email address.", 'error');
        }

        $stmt->close();
    } elseif (isset($_POST['resend_email']) && $_POST['resend_email'] == '1') {
        // Handle resend email logic
        $message = resendFailedEmail();
        displayMessage($message, strpos($message, 'could not be sent') === false ? 'success' : 'error');
    }
}
?>
