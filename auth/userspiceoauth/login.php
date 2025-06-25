<?php
/**
 * Entry point for initiating UserSpice OAuth login.
 *
 * @package    auth_userspiceoauth
 * @copyright  2023 UserSpice OAuth Integrator (AI)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php'); // Moodle config.php

require_login(0, false); // User does not need to be logged in. Guest login is not allowed.

$authsequence = get_enabled_auth_plugins(true); // Get enabled auth plugins.
if (!in_array('userspiceoauth', $authsequence)) {
    print_error('UserSpice OAuth plugin is not enabled.'); // Or redirect to login page with error.
}

// Get an instance of the auth plugin.
$authplugin = get_auth_plugin('userspiceoauth');

if (!$authplugin) {
    print_error('Could not load UserSpice OAuth plugin.');
}

// Check if current user is already logged in.
if (isloggedin() && !isguestuser()) {
    // Already logged in, redirect to homepage or course page.
    redirect(new moodle_url('/'));
}

// Initiate the OAuth flow. This will usually result in a redirect.
try {
    $authplugin->initiate_oauth_flow();
} catch (Exception $e) {
    // Log the error and show a user-friendly message.
    mtrace("UserSpice OAuth login initiation failed: " . $e->getMessage());
    print_error('An error occurred while trying to log you in via UserSpice. Please try again later or contact support.', null, null, $e->getMessage());
}

// Should not reach here if redirect happens.
exit;
