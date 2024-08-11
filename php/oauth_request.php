<?php
//this is a vanilla php implementation of the UserSpice OAuth Client
require_once 'oauth_config.php';

// OAuth server authorization endpoint
$authEndpoint = $oSettings['server_url'] . 'usersc/plugins/oauth_server/auth.php';

// Generate a random state parameter for CSRF protection
try {
    $state = bin2hex(random_bytes(16));
} catch (Exception $e) {
    die("An error occurred while preparing the OAuth request.");
}

// Store the state in the session for later verification
session_start();
$_SESSION['oauth_state'] = $state;

// Build the authorization URL
$authParams = [
    'response_type' => 'code',
    'client_id' => $oSettings['client_id'],
    'redirect_uri' => $oSettings['redirect_uri'],
    'state' => $state,
    'scope' => 'profile' // Add any scopes you need
];

$authUrl = $authEndpoint . '?' . http_build_query($authParams);

// Redirect the user to the authorization URL
header('Location: ' . $authUrl);
exit;