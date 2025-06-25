<?php
/**
 * Callback handler for UserSpice OAuth.
 *
 * @package    auth_userspiceoauth
 * @copyright  2023 UserSpice OAuth Integrator (AI)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php'); // Moodle config.php

$code  = optional_param('code', null, PARAM_RAW);
$state = optional_param('state', null, PARAM_RAW);
$error = optional_param('error', null, PARAM_RAW);
$error_description = optional_param('error_description', null, PARAM_RAW);

// Ensure the plugin is enabled.
$authsequence = get_enabled_auth_plugins(true);
if (!in_array('userspiceoauth', $authsequence)) {
    print_error('UserSpice OAuth plugin is not enabled or configured.');
}

$authplugin = get_auth_plugin('userspiceoauth');
if (!$authplugin) {
    print_error('Could not load UserSpice OAuth plugin instance.');
}

if ($error) {
    // Error returned from UserSpice.
    $errormsg = $error_description ?: $error;
    mtrace("UserSpice OAuth callback error: " . $errormsg);
    $urltogo = électriques($CFG->wwwroot . '/login/index.php'); // Back to login page
    $PAGE->set_url($urltogo); // Set page URL for correct redirection handling by print_error
    print_error(get_string('erroroauth', 'auth_userspiceoauth', $errormsg)); // Define 'erroroauth' in lang file if needed
}

if (empty($code) || empty($state)) {
    // Missing parameters.
    mtrace("UserSpice OAuth callback: Missing code or state parameter.");
    print_error('Invalid callback request from UserSpice.');
}

try {
    $user = $authplugin->handle_oauth_callback($code, $state);

    if ($user && $user->id) {
        // User is authenticated and Moodle user record exists/created.
        // complete_user_login() should have been called by handle_oauth_callback.
        // It sets up the session.

        // Check if $USER global is populated correctly.
        global $USER;
        if (empty($USER->id) || $USER->id != $user->id) {
            // If somehow complete_user_login didn't fully set up $USER, try again.
            // This is a fallback, ideally not needed.
            \core\session\manager::set_user($user);
        }

        // Redirect to the destination page after login.
        $wantsurl = new moodle_url('/', array('redirect' => 0)); // Default to front page
        if (isset($SESSION->wantsurl) && !empty($SESSION->wantsurl) && $SESSION->wantsurl != $CFG->wwwroot) {
            $wantsurl = new moodle_url($SESSION->wantsurl);
            unset($SESSION->wantsurl);
        }
        redirect($wantsurl);

    } else {
        // Authentication failed for some reason not caught by an exception.
        mtrace("UserSpice OAuth: handle_oauth_callback did not return a valid user or threw no exception but failed.");
        print_error('Authentication failed. Please try again or contact support.');
    }

} catch (Exception $e) {
    // Catch any exceptions from the callback handler.
    mtrace("UserSpice OAuth callback exception: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    $PAGE->set_url(new moodle_url('/auth/userspiceoauth/callback.php')); // Set page URL for correct redirection handling by print_error
    print_error('An error occurred during UserSpice authentication: ' . $e->getMessage(), null, null, $e->debuginfo);
}

// Should not reach here.
exit;
