<?php
/**
 * UserSpice OAuth Authentication Plugin: main class
 *
 * @package    auth_userspiceoauth
 * @copyright  2023 UserSpice OAuth Integrator (AI)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/authlib.php');
require_once($CFG->libdir . '/libclasses.php'); // For \core\http\client

use \core\http\client as http_client;

class auth_plugin_userspiceoauth extends auth_plugin_base {

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'userspiceoauth';
        $this->config = get_config('auth_userspiceoauth');
        // Moodle uses $this->config->fieldname for settings.
    }

    /**
     * Main login method.
     * For OAuth, this is usually triggered by a redirect from a specific login link,
     * rather than username/password submission.
     * If a username/password is submitted to Moodle's standard login form,
     * this plugin should probably ignore it unless it's configured as the primary auth.
     *
     * @param string $username The username (not used here for OAuth)
     * @param string $password The password (not used here for OAuth)
     * @return bool True if the user is authenticated, false otherwise.
     */
    public function user_login($username, $password) {
        // This plugin relies on the OAuth flow, not direct username/password.
        // If Moodle tries to call this with credentials, it means something else happened.
        return false;
    }

    /**
     * Initiates the OAuth flow by redirecting to UserSpice.
     * This method would be called by a specific entry point, e.g., a login button link.
     */
    public function initiate_oauth_flow() {
        global $SESSION, $CFG;

        if (empty($this->config->client_id) || empty($this->config->userspice_server_url)) {
            throw new \moodle_exception('errorconfigmissing', 'auth_userspiceoauth');
        }

        $state = bin2hex(random_bytes(16));
        $SESSION->userspiceoauth_state = $state;

        $serverUrl = rtrim($this->config->userspice_server_url, '/');
        $authEndpointPath = !empty($this->config->us_auth_endpoint_path) ? $this->config->us_auth_endpoint_path : 'usersc/plugins/oauth_server/auth.php';
        $redirectUri = new \moodle_url('/auth/userspiceoauth/callback.php');
        $scope = !empty($this->config->scope) ? $this->config->scope : 'profile email';

        $params = [
            'response_type' => 'code',
            'client_id'     => $this->config->client_id,
            'redirect_uri'  => $redirectUri->out(false), // false for not escaped
            'state'         => $state,
            'scope'         => $scope,
        ];

        $authUrl = $serverUrl . '/' . $authEndpointPath . '?' . http_build_query($params);
        redirect($authUrl); // Moodle's redirect function
    }

    /**
     * Handles the callback from UserSpice, exchanges code for token, fetches user info,
     * and logs in or provisions the user.
     *
     * @param string $code The authorization code from UserSpice.
     * @param string $receivedState The state parameter from UserSpice.
     * @return \core_user\output\myprofile\myprofile_root|false The user object on success, or false on failure.
     * @throws \moodle_exception
     */
    public function handle_oauth_callback($code, $receivedState) {
        global $SESSION, $DB, $CFG;

        // Verify state
        if (empty($SESSION->userspiceoauth_state) || $receivedState !== $SESSION->userspiceoauth_state) {
            unset($SESSION->userspiceoauth_state);
            throw new \moodle_exception('errorinvalidstate', 'auth_userspiceoauth');
        }
        unset($SESSION->userspiceoauth_state);

        // Exchange code for token
        $tokenData = $this->exchange_code_for_token($code);
        if (empty($tokenData) || empty($tokenData['access_token'])) {
            $errorDetails = $tokenData['error_description'] ?? $tokenData['error'] ?? 'Unknown token error';
            mtrace("UserSpice OAuth: Token exchange failed. Details: " . $errorDetails);
            throw new \moodle_exception('errornotoken', 'auth_userspiceoauth', null, $errorDetails);
        }

        // Fetch user info
        $userInfo = $this->fetch_userspice_user_info($tokenData['access_token']);
        if (empty($userInfo)) {
            mtrace("UserSpice OAuth: Failed to fetch user info.");
            throw new \moodle_exception('errornouserinfo', 'auth_userspiceoauth');
        }

        // Map UserSpice fields to Moodle fields
        $usEmailField = !empty($this->config->map_email) ? $this->config->map_email : 'email';
        $usUserEmail = $userInfo[$usEmailField] ?? null;

        if (empty($usUserEmail)) {
            mtrace("UserSpice OAuth: Email not found in user info. Field searched: " . $usEmailField);
            throw new \moodle_exception('errornoemail', 'auth_userspiceoauth');
        }

        // Check if user exists in Moodle by email
        $moodleUser = $DB->get_record('user', ['email' => $usUserEmail, 'mnethostid' => $CFG->mnet_localhost_id, 'deleted' => 0]);

        if ($moodleUser) {
            // User exists, update if configured
            if (!empty($this->config->update_user_info_on_login)) {
                $this->update_moodle_user_record($moodleUser, $userInfo);
            }
            // Complete login for existing user
            return complete_user_login($moodleUser);
        } else {
            // User does not exist, create if configured
            if (empty($this->config->create_moodle_user)) {
                throw new \moodle_exception('errorusernotfound_nocreate', 'auth_userspiceoauth');
            }
            $newUser = $this->create_moodle_user_record($userInfo);
            if (!$newUser) {
                throw new \moodle_exception('errorusercreationfailed', 'auth_userspiceoauth');
            }
            // Complete login for new user
            return complete_user_login($newUser);
        }
        return false; // Should not reach here
    }

    protected function exchange_code_for_token($code) {
        $serverUrl = rtrim($this->config->userspice_server_url, '/');
        $tokenEndpointPath = !empty($this->config->us_token_endpoint_path) ? $this->config->us_token_endpoint_path : 'usersc/plugins/oauth_server/auth.php';
        $tokenUrl = $serverUrl . '/' . $tokenEndpointPath;
        $redirectUri = new \moodle_url('/auth/userspiceoauth/callback.php');

        $params = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $redirectUri->out(false),
            'client_id'     => $this->config->client_id,
            'client_secret' => $this->config->client_secret,
        ];

        try {
            $client = new http_client();
            $response = $client->post($tokenUrl, $params);
            if ($response->get_status_code() == 200) {
                return json_decode($response->get_body(), true);
            } else {
                mtrace("UserSpice OAuth Token API Error: HTTP " . $response->get_status_code() . " Body: " . $response->get_body());
                $errorBody = json_decode($response->get_body(), true);
                return ['error' => $errorBody['error'] ?? 'api_error', 'error_description' => $errorBody['error_description'] ?? 'API returned HTTP ' . $response->get_status_code()];
            }
        } catch (\Exception $e) {
            mtrace("UserSpice OAuth Token HTTP Exception: " . $e->getMessage());
            return ['error' => 'http_exception', 'error_description' => $e->getMessage()];
        }
        return null;
    }

    protected function fetch_userspice_user_info($accessToken) {
        $serverUrl = rtrim($this->config->userspice_server_url, '/');
        $userInfoEndpointPath = !empty($this->config->us_userinfo_endpoint_path) ? $this->config->us_userinfo_endpoint_path : 'usersc/plugins/oauth_server/api.php';
        $userInfoUrl = $serverUrl . '/' . $userInfoEndpointPath;

        $params = ['access_token' => $accessToken]; // UserSpice simple API often expects token in query

        try {
            $client = new http_client();
            // Check if UserSpice API supports Bearer token, otherwise use query param
            // $response = $client->get($userInfoUrl, ['headers' => ['Authorization' => 'Bearer ' . $accessToken]]);
            $response = $client->get($userInfoUrl . '?' . http_build_query($params));

            if ($response->get_status_code() == 200) {
                return json_decode($response->get_body(), true);
            } else {
                mtrace("UserSpice OAuth UserInfo API Error: HTTP " . $response->get_status_code() . " Body: " . $response->get_body());
            }
        } catch (\Exception $e) {
            mtrace("UserSpice OAuth UserInfo HTTP Exception: " . $e->getMessage());
        }
        return null;
    }

    protected function create_moodle_user_record($userInfo) {
        global $CFG, $DB;

        $usEmailField    = !empty($this->config->map_email) ? $this->config->map_email : 'email';
        $usFirstnameField= !empty($this->config->map_firstname) ? $this->config->map_firstname : 'fname';
        $usLastnameField = !empty($this->config->map_lastname) ? $this->config->map_lastname : 'lname';
        $usUsernameField = !empty($this->config->map_username) ? $this->config->map_username : 'username';

        $user = new \stdClass();
        $user->auth      = $this->authtype;
        $user->email     = $userInfo[$usEmailField] ?? null;
        $user->firstname = $userInfo[$usFirstnameField] ?? 'UserSpice';
        $user->lastname  = $userInfo[$usLastnameField] ?? 'User';
        $user->username  = $userInfo[$usUsernameField] ?? null;

        if (empty($user->username)) { // Generate username if not provided or empty
             $emailparts = explode('@', $user->email);
             $user->username = $emailparts[0];
        }
        // Ensure username is unique.
        $user->username = $DB->sql_unique_shorten_text($user->username, 100); // Max length 100 for username.
        if (\core_user::get_user_by_username($user->username)) {
            $user->username = $user->username . dechex(time()) . dechex(rand(0,15)); // Add timestamp/randomness
            $user->username = $DB->sql_unique_shorten_text($user->username, 100);
        }

        $user->password    = AUTH_PASSWORD_NOT_CACHED; // External auth, password not stored in Moodle.
        $user->confirmed   = 1;
        $user->mnethostid  = $CFG->mnet_localhost_id;
        $user->idnumber    = ''; // Optional: Map from UserSpice if available
        $user->city        = $userInfo['city'] ?? ''; // Example of optional mapping
        $user->country     = $userInfo['country'] ?? ''; // Example

        // Any other fields from UserSpice can be mapped here to $user object.
        // e.g., $user->department, $user->institution etc.

        $user->id = \create_user_record($user->username, $user->password, $user->auth);
        if (!$user->id) {
            mtrace("Error creating Moodle user record for " . $user->email);
            return false;
        }
        // Update the newly created user with the rest of the profile data.
        if (!\update_user_record($user->id, $user)) { // Use update_user_record to set other fields
             mtrace("Error updating Moodle user record with profile data for " . $user->email);
            // User still created, but profile data might be incomplete.
        }

        // Trigger user created event
        $event = \core\event\user_created::create(array(
            'objectid' => $user->id,
            'context' => \context_user::instance($user->id),
            'other' => array('username' => $user->username, 'firstname' => $user->firstname, 'lastname' => $user->lastname, 'email' => $user->email)
        ));
        $event->trigger();

        return \core_user::get_user($user->id);
    }

    protected function update_moodle_user_record(\stdClass $moodleuser, array $userInfo) {
        $usFirstnameField = !empty($this->config->map_firstname) ? $this->config->map_firstname : 'fname';
        $usLastnameField  = !empty($this->config->map_lastname) ? $this->config->map_lastname : 'lname';
        // Email is key, usually not updated this way unless specifically allowed.
        // Username also usually not changed after creation.

        $update = false;
        $usFirstname = $userInfo[$usFirstnameField] ?? null;
        $usLastname  = $userInfo[$usLastnameField] ?? null;

        if ($usFirstname && $moodleuser->firstname !== $usFirstname) {
            $moodleuser->firstname = $usFirstname;
            $update = true;
        }
        if ($usLastname && $moodleuser->lastname !== $usLastname) {
            $moodleuser->lastname = $usLastname;
            $update = true;
        }

        // Add other fields to update if needed.
        // e.g., $moodleuser->city = $userInfo['city'] ?? $moodleuser->city;

        if ($update) {
            if (!\update_user_record($moodleuser->id, $moodleuser)) { // Use update_user_record
                 mtrace("Error updating Moodle user record for " . $moodleuser->username);
            }
            // Trigger user updated event
            $event = \core\event\user_updated::create(array(
                'objectid' => $moodleuser->id,
                'context' => \context_user::instance($moodleuser->id),
                'other' => array('username' => $moodleuser->username) // Add other relevant fields
            ));
            $event->trigger();
        }
    }

    /**
     * Returns a link to initiate login with this provider.
     * This is used by Moodle if $plugin->loginpagelayout = AUTH_LOGINPAGE_LAYOUT_IDPS; is set
     * or if identity providers are listed.
     *
     * @return \moodle_url The URL to start the login process.
     */
    public function loginpage_idp_link() {
        return new \moodle_url('/auth/userspiceoauth/login.php');
    }

    /**
     * Returns the button to display on the login page (if loginpagelayout is IDPS).
     *
     * @return string HTML for the button.
     */
    public function loginpage_idp_branding(\moodle_page $page, $attributename = 'title') {
        // This method is called by Moodle core to display identity provider buttons.
        $buttontext = get_string('login_using_userspiceoauth', 'auth_userspiceoauth');
        $url = $this->loginpage_idp_link();
        return \html_writer::link($url, $buttontext, ['class' => 'btn btn-secondary userspiceoauth-login-button']);
    }

    /**
     * Can the plugin change the user's password?
     *
     * @return bool True if password change is possible, false otherwise.
     */
    public function can_change_password() {
        return false; // Users authenticate via UserSpice, password not managed in Moodle.
    }

    /**
     * Can the plugin reset the user's password?
     *
     * @return bool True if password reset is possible, false otherwise.
     */
    public function can_reset_password() {
        return false; // Password reset should happen on UserSpice.
    }

    /**
     * Returns true if this auth plugin is handling real user authentication.
     * @return boolean
     */
    function is_internal() {
        return false; // Indicates an external authentication method.
    }

    /**
     * Returns true if this auth plugin can be enabled.
     * @return boolean
     */
    function is_enabled() {
        return true; // Can always be enabled from Moodle's perspective.
    }

    /**
     * Prints a review of settings.
     *
     * @return boolean always true
     */
    function config_form($config, $err, $user_fields) {
        // This method is deprecated in Moodle 3.1+, use settings.php instead.
        // include 'config.html'; // Old way
        return true;
    }

    /**
     * Processes the submitted form data from config.html.
     *
     * @param object $config Submitted form data.
     * @return bool True if data is valid and saved, false otherwise.
     */
    function process_config($config) {
        // This method is deprecated in Moodle 3.1+, settings are saved via settings.php.
        return true;
    }
}
