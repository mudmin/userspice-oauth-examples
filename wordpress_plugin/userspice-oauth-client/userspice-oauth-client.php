<?php
/**
 * Plugin Name: UserSpice OAuth Client
 * Plugin URI: https://github.com/mudmin/wordpress-userspice-oauth-client
 * Description: OAuth2 client for UserSpice integration with WordPress
 * Version: 2.0
 * Author: Dan Hoover
 * Author URI: https://userspice.com
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class UserSpice_OAuth_Client {
    private $options;

    public function __construct() {
        $this->options = get_option('userspice_oauth_settings');

        // Initialize the plugin
        add_action('init', array($this, 'init'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_settings_link'));

        // Add settings page
        add_action('admin_menu', array($this, 'add_settings_page'));
        add_action('admin_init', array($this, 'register_settings'));

        // Add login button and move it to the top with JavaScript
        add_action('login_form', array($this, 'add_oauth_section'));
        add_action('login_head', array($this, 'add_oauth_positioning_script'));

        // Handle OAuth callback
        add_action('init', array($this, 'handle_oauth_callback'));
    }

    public function init() {
        // Initialize session if not already started
        if (!session_id()) {
            session_start();
        }
    }

    public function add_settings_page() {
        add_options_page(
            'UserSpice OAuth Settings',
            'UserSpice OAuth',
            'manage_options',
            'userspice-oauth-settings',
            array($this, 'render_settings_page')
        );
    }

    public function register_settings() {
        register_setting('userspice_oauth_settings_group', 'userspice_oauth_settings', array($this, 'sanitize_settings'));

        add_settings_section(
            'userspice_oauth_main_section',
            'OAuth Server Configuration',
            null,
            'userspice-oauth-settings'
        );

        $fields = array(
            'server_url' => array('label' => 'Server URL', 'type' => 'text'),
            'client_id' => array('label' => 'Client ID', 'type' => 'text'),
            'client_secret' => array('label' => 'Client Secret', 'type' => 'password'),
            'redirect_uri' => array('label' => 'Redirect URI', 'type' => 'text'),
            'response_secret' => array('label' => 'Response Secret (HMAC)', 'type' => 'password'),
            'button_label' => array('label' => 'Login Button Label', 'type' => 'text'),
        );

        foreach ($fields as $field => $config) {
            add_settings_field(
                'userspice_oauth_' . $field,
                $config['label'],
                array($this, 'render_settings_field'),
                'userspice-oauth-settings',
                'userspice_oauth_main_section',
                array('field' => $field, 'type' => $config['type'])
            );
        }
    }

    public function sanitize_settings($input) {
        $sanitized = array();

        // Sanitize server URL - ensure trailing slash
        if (isset($input['server_url'])) {
            $sanitized['server_url'] = trailingslashit(esc_url_raw($input['server_url']));
        }

        // Sanitize other text fields
        $text_fields = array('client_id', 'client_secret', 'redirect_uri', 'response_secret', 'button_label');
        foreach ($text_fields as $field) {
            if (isset($input[$field])) {
                $sanitized[$field] = sanitize_text_field($input[$field]);
            }
        }

        return $sanitized;
    }

    public function add_settings_link($links) {
        $settings_link = '<a href="options-general.php?page=userspice-oauth-settings">Settings</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    public function render_settings_page() {
        // Get current full URL for redirect URI suggestion
        $suggested_redirect = home_url('/wp-login.php');
        ?>
        <div class="wrap">
            <h1>UserSpice OAuth Settings</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('userspice_oauth_settings_group');
                do_settings_sections('userspice-oauth-settings');
                submit_button();
                ?>
            </form>

            <hr>
            <h2>Configuration Guide</h2>
            <p>This plugin connects WordPress to a UserSpice instance with the OAuth Server Plugin installed.</p>

            <h3>Server URL</h3>
            <p>The full base URL of your UserSpice OAuth server including the trailing slash.<br>
            <code style="background: #f0f0f0; padding: 3px 8px;">https://your-userspice-domain.com/</code></p>

            <h3>Client ID &amp; Client Secret</h3>
            <p>Create a new OAuth client in your UserSpice admin panel (OAuth Server > Clients) and copy the credentials here.</p>

            <h3>Redirect URI</h3>
            <p>This must <strong>exactly</strong> match what's registered in the UserSpice OAuth server.<br>
            Suggested value: <code style="background: #f0f0f0; padding: 3px 8px;"><?php echo esc_html($suggested_redirect); ?></code></p>

            <h3>Response Secret (HMAC)</h3>
            <p>Optional but recommended for security. If set, the OAuth server will sign response data with HMAC-SHA256
            and this plugin will verify the signature to prevent tampering.<br>
            This must match the 'response_secret' configured for your client in UserSpice.</p>

            <h3>Login Button Label</h3>
            <p>The text displayed on the OAuth login button. Default: "Login with UserSpice"</p>

            <hr>
            <h2>OAuth Flow</h2>
            <ol>
                <li>User visits the WordPress login page</li>
                <li>User clicks the UserSpice OAuth button</li>
                <li>User is redirected to UserSpice for authentication</li>
                <li>After login, user is redirected back with an authorization code</li>
                <li>This plugin exchanges the code for an access token</li>
                <li>User info is retrieved from the /userinfo endpoint</li>
                <li>WordPress user is created (if new) or logged in (if existing)</li>
            </ol>

            <hr>
            <h2>Security Notes</h2>
            <ul>
                <li>Always use HTTPS in production</li>
                <li>Keep your client secret secure</li>
                <li>Use a strong response secret for HMAC verification</li>
                <li>The state parameter provides CSRF protection</li>
            </ul>
        </div>
        <?php
    }

    public function render_settings_field($args) {
        $field = $args['field'];
        $type = isset($args['type']) ? $args['type'] : 'text';
        $value = isset($this->options[$field]) ? esc_attr($this->options[$field]) : '';

        printf(
            '<input type="%s" name="userspice_oauth_settings[%s]" value="%s" class="regular-text">',
            esc_attr($type),
            esc_attr($field),
            $value
        );

        // Add field descriptions
        $descriptions = array(
            'server_url' => 'Include trailing slash (e.g., https://oauth.example.com/)',
            'client_secret' => 'Keep this value secure!',
            'redirect_uri' => 'Must exactly match the OAuth server configuration',
            'response_secret' => 'Optional: Used for HMAC signature verification',
        );

        if (isset($descriptions[$field])) {
            printf('<p class="description">%s</p>', esc_html($descriptions[$field]));
        }
    }

    public function add_oauth_positioning_script() {
        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var oauthSection = document.querySelector('.userspice-oauth-section');
            var usernameField = document.querySelector('#user_login');

            if (oauthSection && usernameField) {
                // Find the username field's parent container
                var usernameContainer = usernameField.closest('p') || usernameField.parentNode;

                // Insert the OAuth section before the username field container
                usernameContainer.parentNode.insertBefore(oauthSection, usernameContainer);
            }
        });
        </script>
        <?php
    }

    public function add_oauth_section() {
        $auth_url = $this->get_authorization_url();
        $button_label = isset($this->options['button_label']) && !empty($this->options['button_label'])
            ? $this->options['button_label']
            : 'Login with UserSpice';

        ?>
        <style>
            .userspice-oauth-section {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 6px;
                padding: 20px;
                margin-bottom: 20px;
                text-align: center;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }

            .userspice-oauth-section h4 {
                margin-top: 0;
                margin-bottom: 12px;
                color: #495057;
                font-size: 16px;
                font-weight: 600;
            }

            .userspice-oauth-button {
                background: linear-gradient(135deg, #007cba 0%, #005a87 100%) !important;
                border: none !important;
                color: white !important;
                padding: 12px 20px !important;
                font-size: 14px !important;
                font-weight: 600 !important;
                text-decoration: none !important;
                border-radius: 4px !important;
                display: inline-block !important;
                transition: all 0.3s ease !important;
                box-shadow: 0 2px 8px rgba(0, 124, 186, 0.3) !important;
                text-transform: none !important;
                letter-spacing: 0.3px !important;
                width: 100% !important;
                box-sizing: border-box !important;
                position: relative !important;
                z-index: 100 !important;
            }

            .userspice-oauth-button:hover {
                background: linear-gradient(135deg, #005a87 0%, #004066 100%) !important;
                transform: translateY(-1px) !important;
                box-shadow: 0 4px 12px rgba(0, 124, 186, 0.4) !important;
                text-decoration: none !important;
                color: white !important;
            }

            .userspice-oauth-button:active {
                transform: translateY(0) !important;
                box-shadow: 0 2px 6px rgba(0, 124, 186, 0.3) !important;
            }

            .oauth-divider {
                display: flex;
                align-items: center;
                margin: 20px 0 0 0;
                color: #666;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            .oauth-divider::before,
            .oauth-divider::after {
                content: '';
                flex: 1;
                height: 1px;
                background: #ddd;
            }

            .oauth-divider span {
                padding: 0 12px;
                background: #f8f9fa;
                position: relative;
                z-index: 1;
            }
        </style>

        <div class="userspice-oauth-section">
            <h4>Quick Login</h4>
            <a href="<?php echo esc_url($auth_url); ?>" class="userspice-oauth-button">
                <?php echo esc_html($button_label); ?>
            </a>
            <div class="oauth-divider">
                <span>Or login with WordPress</span>
            </div>
        </div>
        <?php
    }

    private function get_authorization_url() {
        // Generate cryptographically secure state parameter
        $state = bin2hex(random_bytes(32));
        $_SESSION['oauth_state'] = $state;
        $_SESSION['oauth_state_time'] = time();

        $params = array(
            'response_type' => 'code',
            'client_id' => $this->options['client_id'],
            'redirect_uri' => $this->options['redirect_uri'],
            'state' => $state,
            'scope' => 'profile'
        );

        return $this->options['server_url'] . 'users/auth/?' . http_build_query($params);
    }

    /**
     * Verify HMAC-SHA256 signature using timing-safe comparison
     */
    private function verify_signature($data, $signature, $secret) {
        $expected = hash_hmac('sha256', $data, $secret);
        return hash_equals($expected, $signature);
    }

    public function handle_oauth_callback() {
        // Only process if we have OAuth parameters
        if (!isset($_GET['code']) || !isset($_GET['state'])) {
            return;
        }

        // Verify state parameter (CSRF protection)
        if (!isset($_SESSION['oauth_state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
            wp_die('Invalid state parameter. Possible CSRF attack.', 'OAuth Error', array('response' => 403));
        }

        // Check state expiration (10 minutes)
        if (isset($_SESSION['oauth_state_time']) && (time() - $_SESSION['oauth_state_time']) > 600) {
            wp_die('OAuth state expired. Please try again.', 'OAuth Error', array('response' => 403));
        }

        // Clear state from session
        unset($_SESSION['oauth_state']);
        unset($_SESSION['oauth_state_time']);

        // Get response and signature from URL
        $response = isset($_GET['response']) ? $_GET['response'] : null;
        $signature = isset($_GET['signature']) ? $_GET['signature'] : null;
        $response_secret = isset($this->options['response_secret']) ? $this->options['response_secret'] : '';

        // Verify HMAC signature if configured
        if (!empty($response_secret)) {
            if (empty($signature)) {
                wp_die('Response signature required but not provided.', 'OAuth Error', array('response' => 403));
            }

            $decoded_response = base64_decode($response);
            if (!$this->verify_signature($decoded_response, $signature, $response_secret)) {
                wp_die('Invalid response signature. Data may have been tampered with.', 'OAuth Error', array('response' => 403));
            }
        }

        // Exchange authorization code for access token
        $token_data = $this->exchange_code_for_token($_GET['code']);

        if (isset($token_data['error'])) {
            wp_die('Token exchange error: ' . esc_html($token_data['error']), 'OAuth Error', array('response' => 400));
        }

        if (!isset($token_data['access_token'])) {
            wp_die('No access token received from OAuth server.', 'OAuth Error', array('response' => 400));
        }

        // Fetch user info from /userinfo endpoint
        $user_info = $this->fetch_user_info($token_data['access_token']);

        // Decode the user data from the 'response' parameter (UserSpice-specific)
        $decoded_response = null;
        if ($response) {
            $decoded_response = json_decode(base64_decode($response), true);
        }

        // Use userinfo endpoint data as primary, fall back to response parameter
        $user_data = array();

        if ($user_info && isset($user_info['email'])) {
            $user_data['email'] = $user_info['email'];
            $user_data['name'] = isset($user_info['name']) ? $user_info['name'] : '';
            $user_data['sub'] = isset($user_info['sub']) ? $user_info['sub'] : '';
        }

        // Merge with response data if available
        if ($decoded_response && isset($decoded_response['userdata'])) {
            $response_userdata = $decoded_response['userdata'];
            if (empty($user_data['email']) && isset($response_userdata['email'])) {
                $user_data['email'] = $response_userdata['email'];
            }
            $user_data['fname'] = isset($response_userdata['fname']) ? $response_userdata['fname'] : '';
            $user_data['lname'] = isset($response_userdata['lname']) ? $response_userdata['lname'] : '';
            $user_data['language'] = isset($response_userdata['language']) ? $response_userdata['language'] : '';
        }

        if (empty($user_data['email'])) {
            wp_die('No email address received from OAuth server.', 'OAuth Error', array('response' => 400));
        }

        $this->authenticate_user($user_data);
    }

    /**
     * Fetch user info from the /userinfo endpoint
     */
    private function fetch_user_info($access_token) {
        $userinfo_url = $this->options['server_url'] . 'users/auth/userinfo';

        $response = wp_remote_get($userinfo_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $access_token,
            ),
            'timeout' => 30,
        ));

        if (is_wp_error($response)) {
            error_log('UserSpice OAuth: Failed to fetch user info: ' . $response->get_error_message());
            return null;
        }

        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            error_log('UserSpice OAuth: User info request failed with status ' . $status_code);
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        return json_decode($body, true);
    }

    private function authenticate_user($user_data) {
        $email = sanitize_email($user_data['email']);

        if (!is_email($email)) {
            wp_die('Invalid email address received from OAuth server.', 'OAuth Error', array('response' => 400));
        }

        $user = get_user_by('email', $email);

        if (!$user) {
            // Create a new user
            $username = $email; // Use email as username

            // Generate a secure random password
            $password = wp_generate_password(24, true, true);

            $user_id = wp_create_user($username, $password, $email);

            if (is_wp_error($user_id)) {
                wp_die('Error creating user: ' . esc_html($user_id->get_error_message()), 'OAuth Error', array('response' => 500));
            }

            $user = get_user_by('id', $user_id);

            // Update user meta with additional information
            if (!empty($user_data['fname'])) {
                update_user_meta($user_id, 'first_name', sanitize_text_field($user_data['fname']));
            }
            if (!empty($user_data['lname'])) {
                update_user_meta($user_id, 'last_name', sanitize_text_field($user_data['lname']));
            }
            if (!empty($user_data['language'])) {
                update_user_meta($user_id, 'userspice_language', sanitize_text_field($user_data['language']));
            }
            if (!empty($user_data['sub'])) {
                update_user_meta($user_id, 'userspice_user_id', sanitize_text_field($user_data['sub']));
            }

            // Update display name
            $display_name = trim($user_data['fname'] . ' ' . $user_data['lname']);
            if (!empty($display_name)) {
                wp_update_user(array(
                    'ID' => $user_id,
                    'display_name' => $display_name,
                ));
            }
        } else {
            // Update existing user's metadata if needed
            $user_id = $user->ID;

            if (!empty($user_data['fname'])) {
                update_user_meta($user_id, 'first_name', sanitize_text_field($user_data['fname']));
            }
            if (!empty($user_data['lname'])) {
                update_user_meta($user_id, 'last_name', sanitize_text_field($user_data['lname']));
            }
            if (!empty($user_data['sub'])) {
                update_user_meta($user_id, 'userspice_user_id', sanitize_text_field($user_data['sub']));
            }
        }

        // Log the user in
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);

        // Redirect to home or admin dashboard
        $redirect_to = user_can($user, 'manage_options') ? admin_url() : home_url();
        wp_redirect($redirect_to);
        exit;
    }

    private function exchange_code_for_token($code) {
        $token_url = $this->options['server_url'] . 'users/auth/';

        $response = wp_remote_post($token_url, array(
            'body' => array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->options['redirect_uri'],
                'client_id' => $this->options['client_id'],
                'client_secret' => $this->options['client_secret']
            ),
            'timeout' => 30,
        ));

        if (is_wp_error($response)) {
            return array('error' => $response->get_error_message());
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return array('error' => 'Invalid JSON response from OAuth server');
        }

        return $data;
    }
}

new UserSpice_OAuth_Client();
