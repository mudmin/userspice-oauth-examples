<?php
/**
 * UserSpice OAuth Client - Authorization Response Handler
 *
 * This script handles the OAuth callback after user authorization.
 * It exchanges the authorization code for an access token, then
 * fetches user information from the OAuth server.
 *
 * Flow:
 * 1. OAuth server redirects user here with ?code=xxx&state=xxx
 * 2. Script verifies state parameter to prevent CSRF attacks
 * 3. Script exchanges authorization code for access token
 * 4. Script uses access token to fetch user info from /userinfo endpoint
 * 5. Application can now authenticate/create the user locally
 */

require_once 'oauth_config.php';

session_start();

// Check for OAuth errors returned by the server
if (isset($_GET['error'])) {
    $error = htmlspecialchars($_GET['error']);
    $errorDesc = isset($_GET['error_description'])
        ? htmlspecialchars($_GET['error_description'])
        : 'No description provided';
    die("OAuth Error: $error - $errorDesc");
}

// Get the authorization code and state from query parameters
$authCode = $_GET['code'] ?? null;
$state = $_GET['state'] ?? null;

// Verify required parameters are present
if (!$authCode || !$state) {
    die('Error: Missing authorization code or state parameter.');
}

// Verify the state parameter to prevent CSRF attacks
if (!isset($_SESSION['oauth_state']) || $state !== $_SESSION['oauth_state']) {
    die('Error: Invalid state parameter. Possible CSRF attack.');
}

// Clear the state from session (one-time use)
unset($_SESSION['oauth_state']);

// Exchange the authorization code for an access token
$tokenEndpoint = $oSettings['server_url'] . 'users/auth/';
$tokenResult = exchangeCodeForToken(
    $tokenEndpoint,
    $oSettings['client_id'],
    $oSettings['client_secret'],
    $authCode,
    $oSettings['redirect_uri']
);

if (isset($tokenResult['error'])) {
    die('Token Error: ' . htmlspecialchars($tokenResult['error']) .
        (isset($tokenResult['response']) ? ' - ' . htmlspecialchars($tokenResult['response']) : ''));
}

$accessToken = $tokenResult['access_token'];
$tokenType = $tokenResult['token_type'] ?? 'Bearer';
$expiresIn = $tokenResult['expires_in'] ?? 3600;

// Fetch user information using the access token
$userInfoEndpoint = $oSettings['server_url'] . 'users/auth/userinfo';
$userInfo = fetchUserInfo($userInfoEndpoint, $accessToken);

// Also check for response data passed via GET parameter (UserSpice specific)
// This contains user data and is optionally signed with HMAC-SHA256
$responseData = null;
$signatureVerified = null; // null = no signature, true = verified, false = failed

if (isset($_GET['response'])) {
    $encodedResponse = $_GET['response'];
    $decodedResponse = base64_decode($encodedResponse);

    if ($decodedResponse === false) {
        die('Error: Failed to decode response data.');
    }

    // Check for HMAC signature verification
    $signature = $_GET['signature'] ?? null;
    $responseSecret = $oSettings['response_secret'] ?? '';

    if (!empty($responseSecret)) {
        // We have a secret configured - signature is REQUIRED
        if (empty($signature)) {
            die('Error: Response signature missing but response_secret is configured. Possible tampering.');
        }

        // Verify the HMAC-SHA256 signature (timing-safe comparison)
        $expectedSignature = hash_hmac('sha256', $decodedResponse, $responseSecret);
        if (!hash_equals($expectedSignature, $signature)) {
            die('Error: Invalid response signature. Possible tampering detected.');
        }

        $signatureVerified = true;
    } elseif (!empty($signature)) {
        // Signature provided but no secret configured - warn but continue
        $signatureVerified = false; // Not verified (no secret to check against)
    }

    $responseData = json_decode($decodedResponse, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        die('Error: Failed to parse response data: ' . json_last_error_msg());
    }
}

// At this point, authentication is successful!
// You would typically:
// 1. Check if user exists in your local database (by email or sub/user_id)
// 2. Create the user if they don't exist
// 3. Log the user into your application
// 4. Store the access token if you need to make further API calls

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Authentication Successful</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }
        h1 { color: #28a745; }
        h2 { color: #333; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .token { background: #fff3cd; padding: 10px; border-radius: 5px; word-break: break-all; }
        .info-box { background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .warning { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .error-box { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .signature-verified { color: #28a745; font-weight: bold; }
        .signature-warning { color: #856404; font-weight: bold; }
        .signature-none { color: #6c757d; }
    </style>
</head>
<body>
    <h1>Authentication Successful!</h1>

    <div class="info-box">
        <strong>Access Token:</strong>
        <div class="token"><?= htmlspecialchars($accessToken) ?></div>
        <p><strong>Token Type:</strong> <?= htmlspecialchars($tokenType) ?></p>
        <p><strong>Expires In:</strong> <?= (int)$expiresIn ?> seconds</p>
    </div>

    <h2>User Info from /userinfo Endpoint</h2>
    <?php if ($userInfo && !isset($userInfo['error'])): ?>
        <pre><?= htmlspecialchars(json_encode($userInfo, JSON_PRETTY_PRINT)) ?></pre>
    <?php else: ?>
        <div class="warning">
            <p>Could not fetch user info: <?= htmlspecialchars($userInfo['error'] ?? 'Unknown error') ?></p>
        </div>
    <?php endif; ?>

    <?php if ($responseData): ?>
        <h2>Response Data (UserSpice Specific)</h2>

        <?php if ($signatureVerified === true): ?>
            <p class="signature-verified">HMAC Signature: Verified</p>
        <?php elseif ($signatureVerified === false): ?>
            <div class="warning">
                <p class="signature-warning">HMAC Signature: Not Verified (no response_secret configured in oauth_config.php)</p>
                <p>The server sent a signature but this client has no secret to verify it against. Configure <code>response_secret</code> to enable verification.</p>
            </div>
        <?php else: ?>
            <p class="signature-none">HMAC Signature: None (server did not sign response)</p>
        <?php endif; ?>

        <pre><?= htmlspecialchars(json_encode($responseData, JSON_PRETTY_PRINT)) ?></pre>

        <?php if (isset($responseData['userdata'])): ?>
            <h3>User Data</h3>
            <ul>
                <?php foreach ($responseData['userdata'] as $key => $value): ?>
                    <li><strong><?= htmlspecialchars($key) ?>:</strong> <?= htmlspecialchars(is_array($value) ? json_encode($value) : $value) ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <?php if (isset($responseData['instructions'])): ?>
            <h3>Sync Instructions</h3>
            <ul>
                <?php foreach ($responseData['instructions'] as $key => $value): ?>
                    <li><strong><?= htmlspecialchars($key) ?>:</strong> <?= $value ? 'Yes' : 'No' ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    <?php endif; ?>

    <h2>Next Steps</h2>
    <div class="warning">
        <p>In a production application, you would now:</p>
        <ol>
            <li>Look up the user in your database by their <code>email</code> or <code>sub</code> (user ID)</li>
            <li>Create a new user account if they don't exist</li>
            <li>Log the user into your application session</li>
            <li>Optionally store the access token for future API calls</li>
        </ol>
    </div>

    <h2>Raw Token Response</h2>
    <pre><?= htmlspecialchars(json_encode($tokenResult, JSON_PRETTY_PRINT)) ?></pre>
</body>
</html>
<?php

/**
 * Exchange an authorization code for an access token
 *
 * @param string $tokenUrl    The token endpoint URL
 * @param string $clientId    The OAuth client ID
 * @param string $clientSecret The OAuth client secret
 * @param string $authCode    The authorization code from the callback
 * @param string $redirectUri The redirect URI (must match original request)
 * @return array The token response or error array
 */
function exchangeCodeForToken($tokenUrl, $clientId, $clientSecret, $authCode, $redirectUri) {
    $postData = [
        'grant_type'    => 'authorization_code',
        'code'          => $authCode,
        'redirect_uri'  => $redirectUri,
        'client_id'     => $clientId,
        'client_secret' => $clientSecret,
    ];

    $ch = curl_init($tokenUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($postData),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false) {
        $error = curl_error($ch);
        curl_close($ch);
        return ['error' => 'cURL error: ' . $error];
    }

    curl_close($ch);

    $data = json_decode($response, true);

    if ($httpCode !== 200) {
        return [
            'error'    => $data['error'] ?? 'HTTP ' . $httpCode,
            'response' => $response,
        ];
    }

    return $data;
}

/**
 * Fetch user information from the OAuth server's userinfo endpoint
 *
 * @param string $userInfoUrl  The userinfo endpoint URL
 * @param string $accessToken  The access token
 * @return array The user info or error array
 */
function fetchUserInfo($userInfoUrl, $accessToken) {
    $ch = curl_init($userInfoUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . $accessToken,
            'Accept: application/json',
        ],
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false) {
        $error = curl_error($ch);
        curl_close($ch);
        return ['error' => 'cURL error: ' . $error];
    }

    curl_close($ch);

    $data = json_decode($response, true);

    if ($httpCode !== 200) {
        return [
            'error'    => $data['error'] ?? 'HTTP ' . $httpCode,
            'response' => $response,
        ];
    }

    return $data;
}
