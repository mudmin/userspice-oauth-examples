<?php
/**
 * UserSpice OAuth Authentication Plugin version information.
 *
 * @package    auth_userspiceoauth
 * @copyright  2023 UserSpice OAuth Integrator (AI)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$plugin->component = 'auth_userspiceoauth'; // Full name of the plugin (used for diagnostics).
$plugin->maturity  = MATURITY_ALPHA;      // Alpha, Beta, RC, Stable.
$plugin->release   = 'v1.0.0 (Build: ' . gmdate('Ymd') . '00)'; // Human-readable version name.
$plugin->version   = 2023102800;          // YYYYMMDDHH (This is the release version for Moodle)
$plugin->requires  = 2020110900;          // Requires Moodle 3.10 (YYYYMMDDHH of the Moodle release)
                                          // Adjust if targeting newer Moodle versions specifically.
$plugin->dependencies = array(            // Array of plugin dependencies (component => version)
    'core_auth' => 2020110900,
);
$plugin->supported_features = [AUTH_PLUGIN_SSO_CALLBACK_URL]; // Indicates plugin uses a callback for SSO.
                                                              // Other features: AUTH_PLUGIN_CAN_CHANGE_PASSWORD, etc.
                                                              // AUTH_PLUGIN_HANDLES_LOGIN_BUTTON for custom button on login page.
                                                              // AUTH_PLUGIN_PROVIDES_PROFILE_FIELDS if it syncs extra fields.
                                                              // AUTH_PLUGIN_HAS_CAS_GATEWAY_SUPPORT if it supports CAS-like behavior.

// We might use this if we want Moodle to show our button automatically.
// $plugin->loginpagelayout = AUTH_LOGINPAGE_LAYOUT_IDPS;
// This tells Moodle to use a layout that supports multiple identity providers.
// Alternatively, we can manually add a link/button.
