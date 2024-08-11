<?php
/**
 * Plugin Name: UserSpice OAuth Client
 * Plugin URI: https://github.com/mudmin/wordpress-userspice-oauth-client
 * Description: OAuth2 client for UserSpice integration with WordPress
 * Version: 1.0
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

        // Add login button
        add_action('login_form', array($this, 'add_login_button'));

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
        register_setting('userspice_oauth_settings_group', 'userspice_oauth_settings');

        add_settings_section(
            'userspice_oauth_main_section',
            'Main Settings',
            null,
            'userspice-oauth-settings'
        );

        $fields = array(
            'server_url' => 'Server URL',
            'client_id' => 'Client ID',
            'client_secret' => 'Client Secret',
            'redirect_uri' => 'Redirect URI',
            'button_label' => 'Login Button Label'
        );

        foreach ($fields as $field => $label) {
            add_settings_field(
                'userspice_oauth_' . $field,
                $label,
                array($this, 'render_settings_field'),
                'userspice-oauth-settings',
                'userspice_oauth_main_section',
                array('field' => $field)
            );
        }
    }

    public function add_settings_link($links) {
        $settings_link = '<a href="options-general.php?page=userspice-oauth-settings">Settings</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    public function render_settings_page() {
        //get current full url
        $url = "http://$_SERVER[HTTP_HOST]";
        $url = $url . "/wp-login.php";
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
            <h4>Notes</h4>
            <p>This plugin is designed to connect to a UserSpice instance with the OAuth Server Plugin installed and configured.  Create a new client on that server and copy the settings to this page.</p>
            
            <h5>Server URL</h5>
            <p>This should be the full base url of the server that is running the OAuth Server plugin including the final slash, similar to <span style='color:red;'>https://yourdomain.com/</span></p>

            <h5>Client ID</h5>
            <p>This is the client ID that you created on the UserSpice server.</p>

            <h5>Client Secret</h5>
            <p>This is the client secret that you created on the UserSpice server.</p>

            <h5>Redirect URI</h5>
            <p>This is the full url of the login page on your WordPress site.  It should be similar to
            <span style='color:red;'><?php echo $url?></span>, although you may need to adjust this to your exact url.
            </p>
        </div>
        <?php
    }

    public function render_settings_field($args) {
        $field = $args['field'];
        $value = isset($this->options[$field]) ? $this->options[$field] : '';
        echo "<input type='text' name='userspice_oauth_settings[$field]' value='$value' class='regular-text'>";
    }



    private function get_authorization_url() {
        $state = bin2hex(random_bytes(16));
        $_SESSION['oauth_state'] = $state;

        $params = array(
            'response_type' => 'code',
            'client_id' => $this->options['client_id'],
            'redirect_uri' => $this->options['redirect_uri'],
            'state' => $state,
            'scope' => 'profile'
        );

        return $this->options['server_url'] . 'usersc/plugins/oauth_server/auth.php?' . http_build_query($params);
    }
    public function handle_oauth_callback() {
        if (isset($_GET['code']) && isset($_GET['state'])) {
            if ($_GET['state'] !== $_SESSION['oauth_state']) {
                wp_die('Invalid state parameter');
            }

            $token_data = $this->exchange_code_for_token($_GET['code']);

            if (isset($token_data['error'])) {
                wp_die('Error: ' . $token_data['error']);
            }

            // Decode the user data from the 'response' parameter
            $response = $_GET['response'] ?? null;
            $decoded_response = json_decode(base64_decode($response), true);

            if (!$decoded_response || !isset($decoded_response['userdata']['email'])) {
                wp_die('Error: Invalid user data received');
            }

            $user_data = $decoded_response['userdata'];
            $this->authenticate_user($user_data);
        }
    }

    private function authenticate_user($user_data) {
        // Check if email exists in the user data
        if (empty($user_data['email'])) {
            wp_die('Error: No email provided by the OAuth server');
        }

        $user = get_user_by('email', $user_data['email']);

        if (!$user) {
            // Use email as username
            $username = $user_data['email'];

            // Create a new user
            $user_id = wp_create_user(
                $username,
                wp_generate_password(),
                $user_data['email']
            );

            if (is_wp_error($user_id)) {
                wp_die('Error creating user: ' . $user_id->get_error_message());
            }

            $user = get_user_by('id', $user_id);

            // Optionally, update user meta with additional information
            update_user_meta($user_id, 'first_name', $user_data['fname']);
            update_user_meta($user_id, 'last_name', $user_data['lname']);
            update_user_meta($user_id, 'userspice_language', $user_data['language']);
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID);
        do_action('wp_login', $user->user_login, $user);

        wp_redirect(home_url());
        exit;
    }
    private function exchange_code_for_token($code) {
        $token_url = $this->options['server_url'] . 'usersc/plugins/oauth_server/auth.php';

        $response = wp_remote_post($token_url, array(
            'body' => array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->options['redirect_uri'],
                'client_id' => $this->options['client_id'],
                'client_secret' => $this->options['client_secret']
            )
        ));

        if (is_wp_error($response)) {
            return array('error' => $response->get_error_message());
        }

        $body = wp_remote_retrieve_body($response);
        return json_decode($body, true);
    }

    public function add_login_button() {
        $auth_url = $this->get_authorization_url();
        $button_label = isset($this->options['button_label']) ? $this->options['button_label'] : 'Login with UserSpice';
        echo "<div style='text-align: center; margin-bottom: .7rem;'>";
        echo "<a href='$auth_url' class='button button-secondary' style='width: 100%;'>$button_label</a>";
        echo "</div>";
    }

}

new UserSpice_OAuth_Client();