<?php
/**
 * English language strings for UserSpice OAuth Authentication Plugin.
 *
 * @package    auth_userspiceoauth
 * @copyright  2023 UserSpice OAuth Integrator (AI)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['pluginname'] = 'UserSpice OAuth';
$string['auth_userspiceoauthdescription'] = 'Allows users to log in to Moodle using their UserSpice account via OAuth2. After enabling, configure the settings below. You will also need to ensure the UserSpice OAuth server is configured with the correct callback URL.';

// Settings
$string['config_settings_title'] = 'UserSpice OAuth Settings';
$string['userspice_server_url'] = 'UserSpice Server URL';
$string['userspice_server_url_desc'] = 'The base URL of your UserSpice installation (e.g., https://example.com/usersc/).';
$string['client_id'] = 'Client ID';
$string['client_id_desc'] = 'The Client ID obtained from your UserSpice OAuth Server plugin.';
$string['client_secret'] = 'Client Secret';
$string['client_secret_desc'] = 'The Client Secret obtained from your UserSpice OAuth Server plugin.';

$string['us_auth_endpoint_path'] = 'Authorization Endpoint Path';
$string['us_auth_endpoint_path_desc'] = 'Path to UserSpice authorization endpoint relative to server URL (e.g., usersc/plugins/oauth_server/auth.php). Default: usersc/plugins/oauth_server/auth.php';
$string['us_token_endpoint_path'] = 'Token Endpoint Path';
$string['us_token_endpoint_path_desc'] = 'Path to UserSpice token endpoint relative to server URL (e.g., usersc/plugins/oauth_server/auth.php). Default: usersc/plugins/oauth_server/auth.php';
$string['us_userinfo_endpoint_path'] = 'User Info Endpoint Path';
$string['us_userinfo_endpoint_path_desc'] = 'Path to UserSpice user info API endpoint relative to server URL (e.g., usersc/plugins/oauth_server/api.php). Default: usersc/plugins/oauth_server/api.php';

$string['scope'] = 'Scope';
$string['scope_desc'] = 'Space-separated list of scopes to request (e.g., profile email). `email` is recommended for linking accounts. Default: profile email';

$string['create_moodle_user'] = 'Auto-create Moodle User';
$string['create_moodle_user_desc'] = 'If enabled, a new Moodle user will be created if one doesn\'t exist for the UserSpice account.';
$string['update_user_info_on_login'] = 'Update user info on login';
$string['update_user_info_on_login_desc'] = 'If enabled, user\'s Moodle profile (firstname, lastname, email) will be updated with data from UserSpice upon each login.';

$string['field_mapping_title'] = 'User Field Mapping';
$string['map_firstname'] = 'UserSpice field for Firstname';
$string['map_firstname_desc'] = 'Name of the UserSpice user info field to map to Moodle\'s firstname (e.g., fname, given_name). Default: fname';
$string['map_lastname'] = 'UserSpice field for Lastname';
$string['map_lastname_desc'] = 'Name of the UserSpice user info field to map to Moodle\'s lastname (e.g., lname, family_name). Default: lname';
$string['map_email'] = 'UserSpice field for Email';
$string['map_email_desc'] = 'Name of the UserSpice user info field for email. Default: email';
$string['map_username'] = 'UserSpice field for Username (optional)';
$string['map_username_desc'] = 'Name of the UserSpice user info field for username. If empty, Moodle will generate one or use email prefix. Default: username';
// Add more mappings as needed: city, country, description, etc.

// Login button
$string['login_button_text'] = 'Login with UserSpice';
$string['login_using_userspiceoauth'] = 'Login with UserSpice'; // Used for alt text or titles

// Errors
$string['errorinvalidstate'] = 'Error: Invalid state. CSRF attempt or session issue.';
$string['errornotoken'] = 'Error: Could not obtain access token from UserSpice.';
$string['errornouserinfo'] = 'Error: Could not retrieve user information from UserSpice.';
$string['errornoemail'] = 'Error: UserSpice did not provide an email address.';
$string['errorusernotfound_nocreate'] = 'Error: User account not found in Moodle and auto-creation is disabled.';
$string['errorusercreationfailed'] = 'Error: Failed to create user account in Moodle.';
$string['errorconfigmissing'] = 'UserSpice OAuth plugin is not configured correctly. Please contact an administrator.';
$string['callbackurl'] = 'Callback URL';
$string['callbackurl_desc'] = 'This is the URL you must configure in your UserSpice OAuth Server application settings as the Redirect URI:';
```
