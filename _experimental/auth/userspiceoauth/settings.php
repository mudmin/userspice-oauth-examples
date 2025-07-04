<?php
/**
 * UserSpice OAuth Authentication Plugin settings.
 *
 * @package    auth_userspiceoauth
 * @copyright  2023 UserSpice OAuth Integrator (AI)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

if ($ADMIN->fulltree) { // Settings are only displayed in full admin tree.

    // Title for the settings page
    $settings->add(new admin_setting_heading(
        'auth_userspiceoauth/config_settings_title',
        get_string('config_settings_title', 'auth_userspiceoauth'),
        '' // No additional info needed for the heading itself.
    ));

    // Callback URL (display only for info)
    $callbackurl = new moodle_url('/auth/userspiceoauth/callback.php');
    $settings->add(new admin_setting_heading(
        'auth_userspiceoauth/callbackurl_info',
        get_string('callbackurl', 'auth_userspiceoauth'),
        get_string('callbackurl_desc', 'auth_userspiceoauth') . '<br><code>' . $callbackurl->out(true) . '</code>'
    ));


    // UserSpice Server URL
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/userspice_server_url',
        get_string('userspice_server_url', 'auth_userspiceoauth'),
        get_string('userspice_server_url_desc', 'auth_userspiceoauth'),
        '', // Default value if not set
        PARAM_URL
    ));

    // Client ID
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/client_id',
        get_string('client_id', 'auth_userspiceoauth'),
        get_string('client_id_desc', 'auth_userspiceoauth'),
        '',
        PARAM_RAW
    ));

    // Client Secret
    $settings->add(new admin_setting_configpasswordunmask(
        'auth_userspiceoauth/client_secret',
        get_string('client_secret', 'auth_userspiceoauth'),
        get_string('client_secret_desc', 'auth_userspiceoauth'),
        '',
        PARAM_RAW
    ));

    // Authorization Endpoint Path
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/us_auth_endpoint_path',
        get_string('us_auth_endpoint_path', 'auth_userspiceoauth'),
        get_string('us_auth_endpoint_path_desc', 'auth_userspiceoauth'),
        'usersc/plugins/oauth_server/auth.php',
        PARAM_TEXT
    ));

    // Token Endpoint Path
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/us_token_endpoint_path',
        get_string('us_token_endpoint_path', 'auth_userspiceoauth'),
        get_string('us_token_endpoint_path_desc', 'auth_userspiceoauth'),
        'usersc/plugins/oauth_server/auth.php',
        PARAM_TEXT
    ));

    // User Info Endpoint Path
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/us_userinfo_endpoint_path',
        get_string('us_userinfo_endpoint_path', 'auth_userspiceoauth'),
        get_string('us_userinfo_endpoint_path_desc', 'auth_userspiceoauth'),
        'usersc/plugins/oauth_server/api.php',
        PARAM_TEXT
    ));

    // Scope
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/scope',
        get_string('scope', 'auth_userspiceoauth'),
        get_string('scope_desc', 'auth_userspiceoauth'),
        'profile email',
        PARAM_TEXT
    ));

    // Auto-create Moodle User
    $settings->add(new admin_setting_configcheckbox(
        'auth_userspiceoauth/create_moodle_user',
        get_string('create_moodle_user', 'auth_userspiceoauth'),
        get_string('create_moodle_user_desc', 'auth_userspiceoauth'),
        1 // Default to enabled
    ));

    // Update user info on login
    $settings->add(new admin_setting_configcheckbox(
        'auth_userspiceoauth/update_user_info_on_login',
        get_string('update_user_info_on_login', 'auth_userspiceoauth'),
        get_string('update_user_info_on_login_desc', 'auth_userspiceoauth'),
        1 // Default to enabled
    ));

    // Field Mapping Section Title
    $settings->add(new admin_setting_heading(
        'auth_userspiceoauth/field_mapping_title_heading',
        get_string('field_mapping_title', 'auth_userspiceoauth'),
        ''
    ));

    // Map Firstname
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/map_firstname',
        get_string('map_firstname', 'auth_userspiceoauth'),
        get_string('map_firstname_desc', 'auth_userspiceoauth'),
        'fname', PARAM_TEXT
    ));
    // Map Lastname
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/map_lastname',
        get_string('map_lastname', 'auth_userspiceoauth'),
        get_string('map_lastname_desc', 'auth_userspiceoauth'),
        'lname', PARAM_TEXT
    ));
    // Map Email
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/map_email',
        get_string('map_email', 'auth_userspiceoauth'),
        get_string('map_email_desc', 'auth_userspiceoauth'),
        'email', PARAM_EMAIL // PARAM_EMAIL for validation
    ));
    // Map Username
    $settings->add(new admin_setting_configtext(
        'auth_userspiceoauth/map_username',
        get_string('map_username', 'auth_userspiceoauth'),
        get_string('map_username_desc', 'auth_userspiceoauth'),
        'username', PARAM_TEXT
    ));

    // Add other general auth settings common to many plugins (e.g., lockout, first/last access)
    // These are often handled by Moodle core for auth plugins.
}
