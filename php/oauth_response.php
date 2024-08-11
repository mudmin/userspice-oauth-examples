<?php
//this is a vanilla php implementation of the UserSpice OAuth Client
require_once 'oauth_config.php';

// Get the authorization code and state from the query parameters
$authCode = $_GET['code'] ?? null;
$state = $_GET['state'] ?? null;

// Verify the state to prevent CSRF attacks
session_start();
if ($state !== $_SESSION['oauth_state']) {
    die('Invalid state parameter');
}

// Exchange the authorization code for an access token
$tokenUrl = $oSettings['server_url'] . 'usersc/plugins/oauth_server/auth.php';
$tokenData = exchangeCodeForToken($tokenUrl, $oSettings['client_id'], $oSettings['client_secret'], $authCode, $oSettings['redirect_uri']);

if (isset($tokenData['error'])) {
    die("Error: " . $tokenData['error']);
}

// At this point, authentication is successful
echo "Authentication successful!<br>";
echo "Access Token: " . $tokenData['access_token'] . "<br>";
echo "Expires In: " . $tokenData['expires_in'] . " seconds<br>";

echo "<br>var_dump of token data:<br>";
var_dump($tokenData);
$response = $_GET['response'] ?? null;
$response = json_decode(base64_decode($response), true);
echo "<br>var_dump of response:<br>";
echo "<pre>";
var_dump($response);
echo "</pre>";
echo "<br>Your login function here. You can now use the access token to make authenticated requests.";

// Function to exchange the authorization code for an access token
function exchangeCodeForToken($tokenUrl, $clientId, $clientSecret, $authCode, $redirectUri)
{
    $data = [
        'grant_type' => 'authorization_code',
        'code' => $authCode,
        'redirect_uri' => $redirectUri,
        'client_id' => $clientId,
        'client_secret' => $clientSecret
    ];

    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_POST, true);

    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($result === FALSE) {
        $error = curl_error($ch);
        curl_close($ch);
        return ['error' => 'cURL error: ' . $error];
    }

    curl_close($ch);

    if ($httpCode !== 200) {
        return [
            'error' => 'Failed to get access token. HTTP Code: ' . $httpCode,
            'response' => $result
        ];
    }

    return json_decode($result, true);
}