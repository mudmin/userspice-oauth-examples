<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  Authentication.UserSpiceOAuth
 * @copyright   Copyright (C) 2023 UserSpice OAuth Integrator (AI). All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * UserSpice OAuth Authentication Plugin
 */
class PlgAuthenticationUserSpiceOAuth extends JPlugin
{
    /**
     * Constructor
     *
     * @param   object  &$subject  Event observer
     * @param   array   $config    Configuration
     */
    public function __construct(&$subject, $config)
    {
        parent::__construct($subject, $config);
        // Load plugin parameters.
        $this->params = $this->getPluginParams();
    }

    /**
     * This method is called when the user logs in.
     * If the UserSpice OAuth process is not yet started, it can initiate it.
     * If it's a callback from UserSpice, it processes the response.
     *
     * @param   array   $credentials  Array holding the user credentials
     * @param   array   $options      Array of options
     * @param   object  $response     Authentication response object
     *
     * @return  void
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        $app = JFactory::getApplication();
        $input = $app->input;

        // Check if this is a UserSpice OAuth login initiation or callback
        $isUserSpiceOAuthLogin = $input->get('userspiceoauth', 0, 'INT');
        $isUserSpiceOAuthCallback = $input->get('code', null, 'STRING') && $input->get('state', null, 'STRING');

        if ($isUserSpiceOAuthLogin === 1 && !$isUserSpiceOAuthCallback) {
            // Initiate UserSpice OAuth login
            $this->doUserSpiceLogin($response); // $response might not be used here directly
            return; // Stop further Joomla authentication
        }

        if ($isUserSpiceOAuthCallback) {
            // Handle UserSpice OAuth callback
            $this->handleUserSpiceCallback($response);
            return; // Stop further Joomla authentication
        }

        // If not a UserSpice OAuth action, then this plugin does nothing for standard Joomla login.
        $response->status = JAuthentication::STATUS_FAILURE;
        $response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS'); // Generic message
    }

    /**
     * Initiates the redirect to UserSpice OAuth server.
     */
    protected function doUserSpiceLogin(&$response)
    {
        $app = JFactory::getApplication();
        $session = JFactory::getSession();

        $serverUrl = rtrim($this->params->get('userspice_server_url'), '/');
        $authEndpoint = $this->params->get('us_auth_endpoint_path', 'plugins/oauth_server/auth.php');
        $clientId = $this->params->get('client_id');
        $scope = $this->params->get('scope', 'profile email');

        // The redirect URI for UserSpice should point back to Joomla's root,
        // and we'll detect the callback parameters there.
        // Or, more robustly, a specific task URL for this plugin.
        // For simplicity, let's use the current URL and expect 'code' and 'state'.
        $redirectUri = JURI::getInstance()->toString(['scheme', 'host', 'port', 'path']);
        // Ensure it's the base site URL if on an admin page or such
        $redirectUri = JURI::root() . 'index.php'; // A common callback point

        if (empty($clientId) || empty($serverUrl)) {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('PLG_AUTHENTICATION_USERSPICEOAUTH_ERROR_CONFIG_MISSING');
            $app->enqueueMessage(JText::_('PLG_AUTHENTICATION_USERSPICEOAUTH_ERROR_CONFIG_MISSING_ADMIN'), 'error');
            return;
        }

        // Generate and store state for CSRF protection
        $state = JUserHelper::genRandomPassword(32);
        $session->set('userspiceoauth_state', $state);

        $authUrl = $serverUrl . '/' . $authEndpoint .
            '?response_type=code' .
            '&client_id=' . urlencode($clientId) .
            '&redirect_uri=' . urlencode($redirectUri) .
            '&state=' . urlencode($state) .
            '&scope=' . urlencode($scope);

        $app->redirect($authUrl);
        // Execution stops after redirect
    }

    /**
     * Handles the callback from UserSpice OAuth server.
     */
    protected function handleUserSpiceCallback(&$response)
    {
        $app = JFactory::getApplication();
        $input = $app->input;
        $session = JFactory::getSession();

        $code = $input->getString('code');
        $receivedState = $input->getString('state');
        $storedState = $session->get('userspiceoauth_state', null);

        // Verify state
        if (empty($storedState) || $receivedState !== $storedState) {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('PLG_AUTHENTICATION_USERSPICEOAUTH_ERROR_INVALID_STATE');
            $session->clear('userspiceoauth_state');
            return;
        }
        $session->clear('userspiceoauth_state');

        // Exchange code for token
        $tokenData = $this->exchangeCodeForToken($code);

        if (!$tokenData || isset($tokenData->error) || !isset($tokenData->access_token)) {
            $response->status = JAuthentication::STATUS_FAILURE;
            $errMsg = isset($tokenData->error_description) ? $tokenData->error_description : (isset($tokenData->error) ? $tokenData->error : JText::_('PLG_AUTHENTICATION_USERSPICEOAUTH_ERROR_TOKEN_EXCHANGE'));
            $response->error_message = $errMsg;
            JLog::add('UserSpice OAuth: Token exchange failed. Response: ' . print_r($tokenData, true), JLog::ERROR, 'userspiceoauth');
            return;
        }

        // Fetch user info from UserSpice
        $userInfo = $this->fetchUserSpiceUserInfo($tokenData->access_token);

        if (!$userInfo || isset($userInfo->error) || !isset($userInfo->email)) { // Assuming email is primary identifier
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('PLG_AUTHENTICATION_USERSPICEOAUTH_ERROR_USER_INFO');
             JLog::add('UserSpice OAuth: User info fetch failed. Response: ' . print_r($userInfo, true), JLog::ERROR, 'userspiceoauth');
            return;
        }

        // At this point, we have user info. Log them in or create an account.
        $this->authenticateOrProvisionJoomlaUser($userInfo, $response);
    }

    /**
     * Exchanges authorization code for an access token.
     */
    protected function exchangeCodeForToken($code)
    {
        $app = JFactory::getApplication();
        $http = JHttpFactory::getHttp();

        $serverUrl = rtrim($this->params->get('userspice_server_url'), '/');
        $tokenEndpoint = $this->params->get('us_token_endpoint_path', 'plugins/oauth_server/auth.php');
        $clientId = $this->params->get('client_id');
        $clientSecret = $this->params->get('client_secret');
        $redirectUri = JURI::root() . 'index.php'; // Must match what was sent in auth request

        $postData = array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId,
            'client_secret' => $clientSecret
        );

        $tokenUrl = $serverUrl . '/' . $tokenEndpoint;

        try {
            $response = $http->post($tokenUrl, http_build_query($postData), array('Content-Type' => 'application/x-www-form-urlencoded'));
            if ($response->code == 200) {
                return json_decode($response->body);
            } else {
                JLog::add('UserSpice OAuth: Token API Error. HTTP Code: ' . $response->code . ' Body: ' . $response->body, JLog::ERROR, 'userspiceoauth');
                return (object)['error' => 'token_api_error', 'error_description' => 'API returned HTTP ' . $response->code];
            }
        } catch (Exception $e) {
            JLog::add('UserSpice OAuth: Token HTTP Exception: ' . $e->getMessage(), JLog::ERROR, 'userspiceoauth');
            return (object)['error' => 'http_exception', 'error_description' => $e->getMessage()];
        }
        return null;
    }

    /**
     * Fetches user information from UserSpice resource server.
     */
    protected function fetchUserSpiceUserInfo($accessToken)
    {
        $app = JFactory::getApplication();
        $http = JHttpFactory::getHttp();
        $serverUrl = rtrim($this->params->get('userspice_server_url'), '/');
        $userInfoEndpoint = $this->params->get('us_userinfo_endpoint_path', 'plugins/oauth_server/api.php');
        $userInfoUrl = $serverUrl . '/' . $userInfoEndpoint;

        try {
            // UserSpice typically expects token in query param for its simple API
            // $response = $http->get($userInfoUrl . '?access_token=' . $accessToken);
            // Or, if it supports Bearer token:
            $headers = array('Authorization' => 'Bearer ' . $accessToken);
            $response = $http->get($userInfoUrl, $headers);


            if ($response->code == 200) {
                return json_decode($response->body);
            } else {
                 JLog::add('UserSpice OAuth: UserInfo API Error. HTTP Code: ' . $response->code . ' Body: ' . $response->body, JLog::ERROR, 'userspiceoauth');
                return (object)['error' => 'userinfo_api_error', 'error_description' => 'API returned HTTP ' . $response->code];
            }
        } catch (Exception $e) {
            JLog::add('UserSpice OAuth: UserInfo HTTP Exception: ' . $e->getMessage(), JLog::ERROR, 'userspiceoauth');
            return (object)['error' => 'http_exception', 'error_description' => $e->getMessage()];
        }
        return null;
    }

    /**
     * Authenticates or provisions a Joomla user based on UserSpice info.
     */
    protected function authenticateOrProvisionJoomlaUser($userInfo, &$response)
    {
        $app = JFactory::getApplication();
        $db = JFactory::getDbo();

        // Use email as the primary link. UserSpice might also provide a unique ID.
        // UserSpice default API returns: id, username, email, fname, lname, permissions, logintype, last_login, account_owner, dev_perm_level, csrf
        // We primarily need email, username, and maybe name.

        $email = $userInfo->email ?? null;
        $username = $userInfo->username ?? null; // Or generate one from email if not provided

        if (empty($email)) {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('PLG_AUTHENTICATION_USERSPICEOAUTH_ERROR_NO_EMAIL');
            return;
        }

        if (empty($username)) { // Fallback if username not in scope/returned
            $username = JUserHelper::suggestUsername($email);
        }


        $joomlaUserId = JUserHelper::getUserId($email);

        if ($joomlaUserId) { // User exists by email
            $user = JFactory::getUser($joomlaUserId);
        } else { // User does not exist, try by username if different
            $joomlaUserIdByUsername = JUserHelper::getUserId($username);
            if($joomlaUserIdByUsername) {
                 $user = JFactory::getUser($joomlaUserIdByUsername);
            } else {
                // User does not exist, create if allowed
                if ($this->params->get('create_joomla_user', 1) == 0) {
                    $response->status = JAuthentication::STATUS_FAILURE;
                    $response->error_message = JText::_('PLG_AUTHENTICATION_USERSPICEOAUTH_ERROR_NO_AUTOCREATE');
                    return;
                }

                $user = new JUser;
                $userData = array(
                    'name' => ($userInfo->fname ?? '') . ' ' . ($userInfo->lname ?? $username),
                    'username' => $username,
                    'email' => $email,
                    'password' => JUserHelper::genRandomPassword(32), // Set a random password, user won't use it
                    'groups' => array((int)$this->params->get('default_user_group', 2)), // Registered by default
                    'block' => 0,
                    'sendEmail' => 0, // Don't send system emails for this
                    'requireReset' => 0
                );

                // Bind data to user object
                if (!$user->bind($userData)) {
                    $response->status = JAuthentication::STATUS_FAILURE;
                    $response->error_message = JText::sprintf('JLIB_USER_ERROR_BINDING_DATA', $user->getError());
                    return;
                }

                // Save user
                if (!$user->save()) {
                    $response->status = JAuthentication::STATUS_FAILURE;
                    $response->error_message = JText::sprintf('JLIB_USER_ERROR_STORING_DATA', $user->getError());
                    return;
                }
            }
        }

        // If user is blocked
        if ($user->block) {
            $response->status = JAuthentication::STATUS_FAILURE;
            $response->error_message = JText::_('JGLOBAL_AUTH_USER_BLOCKED');
            return;
        }

        // Successful login
        $response->status = JAuthentication::STATUS_SUCCESS;
        $response->email = $user->email;
        $response->username = $user->username;
        $response->fullname = $user->name;
        $response->language = $user->getParam('language');
        $response->type = 'UserSpiceOAuth'; // Important for some session management
        $response->error_message = ''; // Clear any previous error

        // Perform Joomla login actions (session, etc.)
        // This is typically handled by Joomla after onUserAuthenticate returns success.
        // $app->login($user->getProperties(), array('remember' => $this->params->get('remember', 0)));
        // $app->setUserState('users.id', $user->id);
        // $app->setUserState('users.isRoot', $user->authorise('core.admin'));

        // For Joomla 3.x, just setting response properties is usually enough.
        // Joomla itself will handle session creation based on $response.
    }

    /**
     * This event is triggered after the framework has loaded and the application initialise method has been called.
     * We can use it to display a button on the login page.
     * Note: This is a common but not always robust way. Template overrides or specific module integration is better.
     * A simpler way is to instruct users to go to: index.php?option=com_users&view=login&userspiceoauth=1
     */
    public function onAfterInitialise()
    {
        $app = JFactory::getApplication();
        if ($app->isClient('site') && $app->input->get('option') === 'com_users' && $app->input->get('view') === 'login') {
            // This is a very basic way to add info. A template override for com_login is better.
            // Or, this plugin could provide a module that users can place.
            // For this example, we will assume the user creates a menu item or custom HTML module
            // that links to `index.php?userspiceoauth=1` or a more specific SEF URL.
            // JFactory::getDocument()->addScriptDeclaration('// JS to add button dynamically could go here');
        }
    }

    /**
     * Utility function to get plugin parameters.
     *
     * @return  JRegistry  Plugin parameters
     */
    protected function getPluginParams()
    {
        $db    = JFactory::getDbo();
        $query = $db->getQuery(true)
            ->select($db->quoteName('params'))
            ->from($db->quoteName('#__extensions'))
            ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
            ->where($db->quoteName('element') . ' = ' . $db->quote('userspiceoauth'))
            ->where($db->quoteName('folder') . ' = ' . $db->quote('authentication'));
        $db->setQuery($query);
        $params = $db->loadResult();

        $registry = new JRegistry;
        $registry->loadString($params);
        return $registry;
    }
}
