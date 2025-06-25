<?php
/**
 * Plugin Name:       WooCommerce UserSpice OAuth Login
 * Plugin URI:        https://example.com/woocommerce-userspice-oauth
 * Description:       Allows customers to log in or register on your WooCommerce store using their UserSpice account via OAuth2.
 * Version:           1.0.0
 * Author:            UserSpice OAuth Integrator (AI)
 * Author URI:        https://www.userspice.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       woocommerce-userspice-oauth
 * Domain Path:       /languages
 * WC requires at least: 3.0
 * WC tested up to: 8.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

// Define constants
define( 'WC_USERSPICE_OAUTH_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WC_USERSPICE_OAUTH_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WC_USERSPICE_OAUTH_VERSION', '1.0.0' );

class WooCommerce_UserSpice_OAuth {

    private static $instance;
    private $settings;

    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->settings = get_option( 'wc_userspice_oauth_settings', [] );

        add_action( 'plugins_loaded', [ $this, 'check_woocommerce_active' ] );
        add_action( 'init', [ $this, 'handle_oauth_callback' ] );

        // Add settings page
        add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );

        // Add login button to WooCommerce forms
        add_action( 'woocommerce_login_form_start', [ $this, 'display_login_button' ] );
        add_action( 'woocommerce_register_form_start', [ $this, 'display_login_button' ] );
        // Or use 'woocommerce_before_customer_login_form' for a more general spot

        // Load plugin textdomain for translations
        add_action( 'plugins_loaded', [ $this, 'load_textdomain' ] );
    }

    public function check_woocommerce_active() {
        if ( ! class_exists( 'WooCommerce' ) ) {
            add_action( 'admin_notices', [ $this, 'woocommerce_not_active_notice' ] );
            // Deactivate self? Or just show notice. For now, just notice.
        }
    }

    public function woocommerce_not_active_notice() {
        ?>
        <div class="notice notice-error">
            <p><?php _e( 'WooCommerce UserSpice OAuth Login requires WooCommerce to be active.', 'woocommerce-userspice-oauth' ); ?></p>
        </div>
        <?php
    }

    public function load_textdomain() {
        load_plugin_textdomain(
            'woocommerce-userspice-oauth',
            false,
            dirname( plugin_basename( __FILE__ ) ) . '/languages'
        );
    }

    public function add_admin_menu() {
        add_options_page(
            __( 'UserSpice OAuth', 'woocommerce-userspice-oauth' ),
            __( 'UserSpice OAuth', 'woocommerce-userspice-oauth' ),
            'manage_options',
            'wc_userspice_oauth',
            [ $this, 'settings_page_html' ]
        );
    }

    public function register_settings() {
        register_setting( 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_settings', [ $this, 'sanitize_settings' ] );

        add_settings_section(
            'wc_userspice_oauth_main_section',
            __( 'UserSpice OAuth Server Details', 'woocommerce-userspice-oauth' ),
            null,
            'wc_userspice_oauth_options_group'
        );

        add_settings_field( 'userspice_server_url', __( 'UserSpice Server URL', 'woocommerce-userspice-oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'url', 'name' => 'userspice_server_url', 'desc' => __( 'Base URL of your UserSpice installation (e.g., https://example.com/usersc/).', 'woocommerce-userspice-oauth' )] );
        add_settings_field( 'client_id', __( 'Client ID', 'woocommerce-userspice-oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'text', 'name' => 'client_id', 'desc' => __( 'Client ID from UserSpice OAuth Server.', 'woocommerce-userspice-oauth' )] );
        add_settings_field( 'client_secret', __( 'Client Secret', 'woocommerce-userspice-oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'password', 'name' => 'client_secret', 'desc' => __( 'Client Secret from UserSpice OAuth Server.', 'woocommerce-userspice-oauth' )] );
        add_settings_field( 'us_auth_endpoint_path', __( 'Auth Endpoint Path', 'woocommerce-userspice-oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'text', 'name' => 'us_auth_endpoint_path', 'default' => 'usersc/plugins/oauth_server/auth.php', 'desc' => __( 'Relative path to auth endpoint.', 'woocommerce-userspice-oauth' )] );
        add_settings_field( 'us_token_endpoint_path', __( 'Token Endpoint Path', 'woocommerce-userspice-oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'text', 'name' => 'us_token_endpoint_path', 'default' => 'usersc/plugins/oauth_server/auth.php', 'desc' => __( 'Relative path to token endpoint.', 'woocommerce-userspice-oauth' )] );
        add_settings_field( 'us_userinfo_endpoint_path', __( 'User Info Endpoint Path', 'woocommerce-userspice_oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'text', 'name' => 'us_userinfo_endpoint_path', 'default' => 'usersc/plugins/oauth_server/api.php', 'desc' => __( 'Relative path to user info API.', 'woocommerce-userspice_oauth' )] );
        add_settings_field( 'scope', __( 'Scope', 'woocommerce-userspice-oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'text', 'name' => 'scope', 'default' => 'profile email', 'desc' => __( 'Space-separated scopes (e.g., profile email).', 'woocommerce-userspice_oauth' )] );
        add_settings_field( 'auto_create_user', __( 'Auto-create User', 'woocommerce-userspice-oauth' ), [ $this, 'render_settings_field' ], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['type' => 'checkbox', 'name' => 'auto_create_user', 'desc' => __( 'Create a new WordPress user if one doesn\'t exist for the UserSpice account.', 'woocommerce-userspice_oauth' )] );

        $callback_url = add_query_arg( 'wc_userspice_oauth_callback', '1', home_url( '/' ) );
        add_settings_field( 'callback_url_display', __( 'Callback URL', 'woocommerce-userspice-oauth'), [ $this, 'render_callback_url_display'], 'wc_userspice_oauth_options_group', 'wc_userspice_oauth_main_section', ['url' => $callback_url] );

    }

    public function render_callback_url_display( $args ) {
        echo '<code>' . esc_url( $args['url'] ) . '</code>';
        echo '<p class="description">' . __( 'Use this URL as the Redirect URI in your UserSpice OAuth client settings.', 'woocommerce-userspice-oauth' ) . '</p>';
    }

    public function sanitize_settings( $input ) {
        $sanitized_input = [];
        $defaults = [
            'us_auth_endpoint_path' => 'usersc/plugins/oauth_server/auth.php',
            'us_token_endpoint_path' => 'usersc/plugins/oauth_server/auth.php',
            'us_userinfo_endpoint_path' => 'usersc/plugins/oauth_server/api.php',
            'scope' => 'profile email',
            'auto_create_user' => 0,
        ];

        foreach (['userspice_server_url', 'client_id', 'client_secret', 'us_auth_endpoint_path', 'us_token_endpoint_path', 'us_userinfo_endpoint_path', 'scope'] as $key) {
            $sanitized_input[$key] = isset( $input[$key] ) ? sanitize_text_field( $input[$key] ) : ($defaults[$key] ?? '');
        }
        $sanitized_input['userspice_server_url'] = isset( $input['userspice_server_url'] ) ? esc_url_raw( rtrim($input['userspice_server_url'], '/') ) : '';
        $sanitized_input['auto_create_user'] = isset( $input['auto_create_user'] ) ? 1 : 0;

        return $sanitized_input;
    }

    public function render_settings_field( $args ) {
        $value = isset( $this->settings[$args['name']] ) ? $this->settings[$args['name']] : ($args['default'] ?? '');
        $type = $args['type'];
        $name = $args['name'];
        $desc = $args['desc'] ?? '';

        if ( $type === 'checkbox' ) {
            echo "<input type='checkbox' name='wc_userspice_oauth_settings[{$name}]' value='1' " . checked( 1, $value, false ) . " />";
        } elseif ($type === 'password') {
             echo "<input type='password' name='wc_userspice_oauth_settings[{$name}]' value='" . esc_attr( $value ) . "' class='regular-text' />";
        } else {
            echo "<input type='{$type}' name='wc_userspice_oauth_settings[{$name}]' value='" . esc_attr( $value ) . "' class='regular-text' />";
        }
        if ($desc) {
            echo "<p class='description'>{$desc}</p>";
        }
    }

    public function settings_page_html() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
            <form action="options.php" method="post">
                <?php
                settings_fields( 'wc_userspice_oauth_options_group' );
                do_settings_sections( 'wc_userspice_oauth_options_group' );
                submit_button( __( 'Save Settings', 'woocommerce-userspice-oauth' ) );
                ?>
            </form>
        </div>
        <?php
    }

    public function display_login_button() {
        if (is_user_logged_in()) return;

        $client_id = $this->settings['client_id'] ?? '';
        if (empty($client_id)) return; // Don't show if not configured

        $text = apply_filters( 'wc_userspice_oauth_login_button_text', __( 'Login with UserSpice', 'woocommerce-userspice-oauth' ) );
        $redirect_url = add_query_arg( 'wc_userspice_oauth_login', '1', home_url( '/' ) ); // This will trigger the redirect

        echo '<div class="wc-userspice-oauth-login" style="margin-bottom: 15px;">';
        echo '<a href="' . esc_url( $redirect_url ) . '" class="button userspice-oauth-button">' . esc_html( $text ) . '</a>';
        echo '</div>';
    }

    private function get_redirect_uri() {
        return add_query_arg( 'wc_userspice_oauth_callback', '1', home_url( '/' ) );
    }

    public function handle_oauth_callback() {
        // Handle redirect to UserSpice
        if ( isset( $_GET['wc_userspice_oauth_login'] ) && $_GET['wc_userspice_oauth_login'] == '1' ) {
            if (is_user_logged_in()) {
                wp_redirect( wc_get_page_permalink( 'myaccount' ) );
                exit;
            }
            $this->initiate_userspice_redirect();
        }

        // Handle callback from UserSpice
        if ( isset( $_GET['wc_userspice_oauth_callback'] ) && $_GET['wc_userspice_oauth_callback'] == '1' ) {
            if (is_user_logged_in()) { // Should not happen if state is managed properly
                wp_redirect( wc_get_page_permalink( 'myaccount' ) );
                exit;
            }
            $this->process_userspice_callback();
        }
    }

    private function initiate_userspice_redirect() {
        $server_url = $this->settings['userspice_server_url'] ?? '';
        $client_id = $this->settings['client_id'] ?? '';
        $auth_path = $this->settings['us_auth_endpoint_path'] ?? 'usersc/plugins/oauth_server/auth.php';
        $scope = $this->settings['scope'] ?? 'profile email';

        if ( empty( $server_url ) || empty( $client_id ) ) {
            wc_add_notice( __( 'UserSpice OAuth is not configured correctly.', 'woocommerce-userspice-oauth' ), 'error' );
            wp_redirect( wc_get_page_permalink( 'myaccount' ) );
            exit;
        }

        $state = wp_create_nonce( 'wc_userspice_oauth_state' );
        set_transient( 'wc_userspice_oauth_state_transient', $state, HOUR_IN_SECONDS );

        $params = [
            'response_type' => 'code',
            'client_id'     => $client_id,
            'redirect_uri'  => $this->get_redirect_uri(),
            'state'         => $state,
            'scope'         => $scope,
        ];
        $auth_url = esc_url_raw( $server_url . '/' . $auth_path . '?' . http_build_query( $params ) );
        wp_redirect( $auth_url );
        exit;
    }

    private function process_userspice_callback() {
        $code = isset( $_GET['code'] ) ? sanitize_text_field( $_GET['code'] ) : null;
        $received_state = isset( $_GET['state'] ) ? sanitize_text_field( $_GET['state'] ) : null;
        $stored_state = get_transient( 'wc_userspice_oauth_state_transient' );
        delete_transient( 'wc_userspice_oauth_state_transient' );

        if ( ! $code || ! $received_state || ! $stored_state || ! wp_verify_nonce( $received_state, 'wc_userspice_oauth_state' ) || $received_state !== $stored_state ) {
            wc_add_notice( __( 'Invalid OAuth state or code. Please try again.', 'woocommerce-userspice-oauth' ), 'error' );
            wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) );
            exit;
        }

        // Exchange code for token
        $token_data = $this->exchange_code_for_token( $code );
        if ( is_wp_error( $token_data ) || empty( $token_data['access_token'] ) ) {
            $error_message = is_wp_error( $token_data ) ? $token_data->get_error_message() : __( 'Failed to obtain access token.', 'woocommerce-userspice-oauth' );
            wc_add_notice( $error_message, 'error' );
            wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) );
            exit;
        }

        // Fetch user info
        $user_info = $this->fetch_userspice_user_info( $token_data['access_token'] );
         if ( is_wp_error( $user_info ) || empty( $user_info['email'] ) ) { // Assuming email is primary
            $error_message = is_wp_error( $user_info ) ? $user_info->get_error_message() : __( 'Failed to fetch user information from UserSpice.', 'woocommerce-userspice-oauth' );
            wc_add_notice( $error_message, 'error' );
            wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) );
            exit;
        }

        // Login or create user
        $this->login_or_register_user( $user_info );

        // Redirect after login/registration
        wp_safe_redirect( wc_get_page_permalink( 'myaccount' ) ); // Or wc_get_checkout_url(), etc.
        exit;
    }

    private function exchange_code_for_token( $code ) {
        $server_url = $this->settings['userspice_server_url'] ?? '';
        $token_path = $this->settings['us_token_endpoint_path'] ?? 'usersc/plugins/oauth_server/auth.php';
        $token_url = $server_url . '/' . $token_path;

        $body = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->get_redirect_uri(),
            'client_id'     => $this->settings['client_id'] ?? '',
            'client_secret' => $this->settings['client_secret'] ?? '',
        ];

        $response = wp_remote_post( $token_url, [ 'body' => $body, 'timeout' => 15 ] );

        if ( is_wp_error( $response ) ) {
            return new WP_Error('token_request_failed', __( 'Token request failed: ', 'woocommerce-userspice-oauth' ) . $response->get_error_message());
        }

        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = wp_remote_retrieve_body( $response );
        $data = json_decode( $response_body, true );

        if ( $response_code !== 200 || empty( $data['access_token'] ) ) {
            $error = $data['error_description'] ?? $data['error'] ?? __( 'Unknown error during token exchange.', 'woocommerce-userspice-oauth' );
            return new WP_Error('token_exchange_error', $error . ' (HTTP ' . $response_code . ')');
        }
        return $data;
    }

    private function fetch_userspice_user_info( $access_token ) {
        $server_url = $this->settings['userspice_server_url'] ?? '';
        $userinfo_path = $this->settings['us_userinfo_endpoint_path'] ?? 'usersc/plugins/oauth_server/api.php';
        $userinfo_url = $server_url . '/' . $userinfo_path;

        // UserSpice simple API often expects token as query param
        $userinfo_url_with_token = add_query_arg( 'access_token', $access_token, $userinfo_url );

        // $response = wp_remote_get( $userinfo_url_with_token, [ 'timeout' => 15 ] );
        // OR if UserSpice API supports Bearer token for userinfo:
        $response = wp_remote_get( $userinfo_url, [
            'headers' => [ 'Authorization' => 'Bearer ' . $access_token ],
            'timeout' => 15
        ]);


        if ( is_wp_error( $response ) ) {
            return new WP_Error('userinfo_request_failed', __( 'User info request failed: ', 'woocommerce-userspice-oauth' ) . $response->get_error_message());
        }

        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = wp_remote_retrieve_body( $response );
        $data = json_decode( $response_body, true );

        if ( $response_code !== 200 || empty( $data ) ) {
             $error = $data['error_description'] ?? $data['error'] ?? __( 'Unknown error fetching user info.', 'woocommerce-userspice-oauth' );
            return new WP_Error('userinfo_fetch_error', $error . ' (HTTP ' . $response_code . ')');
        }
        return $data; // Expects fields like 'id', 'username', 'email', 'fname', 'lname'
    }

    private function login_or_register_user( $user_info ) {
        $email = sanitize_email( $user_info['email'] );
        $user = get_user_by( 'email', $email );

        if ( $user ) {
            // User exists, log them in.
            wp_set_current_user( $user->ID, $user->user_login );
            wp_set_auth_cookie( $user->ID );
            do_action( 'wp_login', $user->user_login, $user );
        } elseif ( !empty($this->settings['auto_create_user']) && $this->settings['auto_create_user'] == 1 ) {
            // User does not exist, create them.
            $username = sanitize_user( $user_info['username'] ?? '', true );
            if ( empty( $username ) || username_exists( $username ) ) {
                $username = sanitize_user( explode( '@', $email )[0], true );
                 if (username_exists($username)) {
                    $username = $username . '_' . wp_rand(100,999); // Make it more unique
                 }
            }
            // Ensure username is truly unique
            $i = 1;
            $base_username = $username;
            while(username_exists($username)) {
                $username = $base_username . $i;
                $i++;
            }

            $password = wp_generate_password();
            $user_id = wc_create_new_customer( $email, $username, $password ); // WooCommerce function

            if ( is_wp_error( $user_id ) ) {
                wc_add_notice( __( 'Could not create your account: ', 'woocommerce-userspice-oauth' ) . $user_id->get_error_message(), 'error' );
                return;
            }

            // Update user meta like first name, last name
            $us_fname = sanitize_text_field($user_info['fname'] ?? '');
            $us_lname = sanitize_text_field($user_info['lname'] ?? '');
            if ($us_fname) update_user_meta( $user_id, 'first_name', $us_fname );
            if ($us_lname) update_user_meta( $user_id, 'last_name', $us_lname );
            if ($us_fname || $us_lname) update_user_meta( $user_id, 'display_name', trim("$us_fname $us_lname") );

            // Log the new user in
            $new_user = get_user_by( 'id', $user_id );
            wp_set_current_user( $new_user->ID, $new_user->user_login );
            wp_set_auth_cookie( $new_user->ID );
            do_action( 'wp_login', $new_user->user_login, $new_user );
            do_action( 'woocommerce_created_customer', $user_id ); // WooCommerce action
        } else {
            // User doesn't exist and auto-create is off
            wc_add_notice( __( 'Your UserSpice account is not linked to an account on this store, and auto-registration is disabled.', 'woocommerce-userspice-oauth' ), 'notice' );
        }
    }
}

// Instantiate the plugin.
WooCommerce_UserSpice_OAuth::get_instance();

// Activation/Deactivation hooks (optional, for cleanup or setup)
// register_activation_hook( __FILE__, 'wc_userspice_oauth_activate' );
// function wc_userspice_oauth_activate() { ... }
// register_deactivation_hook( __FILE__, 'wc_userspice_oauth_deactivate' );
// function wc_userspice_oauth_deactivate() { ... }

```
