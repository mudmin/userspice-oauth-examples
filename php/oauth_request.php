<?php
/**
 * UserSpice OAuth Client - Authorization Request
 *
 * This script initiates the OAuth 2.0 Authorization Code flow.
 * It redirects the user to the UserSpice OAuth server for authentication.
 *
 * Flow:
 * 1. User visits this page
 * 2. Script generates a CSRF state token and stores it in session
 * 3. User is redirected to the OAuth server's authorization endpoint
 * 4. User logs in and authorizes the application
 * 5. OAuth server redirects back to oauth_response.php with auth code
 */

require_once 'oauth_config.php';

// Start session for state management
session_start();

// OAuth server authorization endpoint
$authEndpoint = $oSettings['server_url'] . 'users/auth/';

// Generate a random state parameter for CSRF protection
try {
    $state = bin2hex(random_bytes(16));
} catch (Exception $e) {
    die('Error: Unable to generate secure state parameter.');
}

// Store the state in session for verification in oauth_response.php
$_SESSION['oauth_state'] = $state;

// Build the authorization URL with required parameters
$authParams = [
    'response_type' => 'code',                    // We want an authorization code
    'client_id'     => $oSettings['client_id'],   // Identifies this application
    'redirect_uri'  => $oSettings['redirect_uri'], // Where to send the user after auth
    'state'         => $state,                     // CSRF protection token
    'scope'         => $oSettings['scope'],        // What permissions we're requesting
];

$authUrl = $authEndpoint . '?' . http_build_query($authParams);

// Redirect the user to the OAuth server for authentication
header('Location: ' . $authUrl);
exit;
