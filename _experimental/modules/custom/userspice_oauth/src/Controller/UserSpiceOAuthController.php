<?php

namespace Drupal\userspice_oauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Drupal\user\UserAuthInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\RequestException;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\externalauth\ExternalAuthInterface; // Optional: if using externalauth module

/**
 * Controller for UserSpice OAuth authentication.
 */
class UserSpiceOAuthController extends ControllerBase {

  /**
   * The HTTP client.
   * @var \GuzzleHttp\ClientInterface
   */
  protected $httpClient;

  /**
   * The current user.
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * The request stack.
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * The UserSpice OAuth configuration.
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The externalauth.auth service. (Optional)
   * @var \Drupal\externalauth\ExternalAuthInterface|null
   */
  // protected $externalAuth;


  /**
   * Constructs a new UserSpiceOAuthController.
   */
  public function __construct(ClientInterface $http_client, AccountProxyInterface $current_user, RequestStack $request_stack, ConfigFactoryInterface $config_factory /*, ExternalAuthInterface $external_auth = NULL */) {
    $this->httpClient = $http_client;
    $this->currentUser = $current_user;
    $this->requestStack = $request_stack;
    $this->config = $config_factory->get('userspice_oauth.settings');
    // $this->externalAuth = $external_auth;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('http_client'),
      $container->get('current_user'),
      $container->get('request_stack'),
      $container->get('config.factory')
      // Optional: $container->has('externalauth.auth') ? $container->get('externalauth.auth') : NULL
    );
  }

  /**
   * Redirects the user to UserSpice for authentication.
   */
  public function redirectToUserSpice() {
    if (!$this->currentUser->isAnonymous()) {
      return $this->redirect('<front>');
    }

    $serverUrl = rtrim($this->config->get('userspice_server_url'), '/');
    $authEndpointPath = $this->config->get('us_auth_endpoint_path');
    $clientId = $this->config->get('client_id');
    $scope = $this->config->get('scope');
    $redirectUri = Url::fromRoute('userspice_oauth.callback', [], ['absolute' => TRUE])->toString();

    if (empty($clientId) || empty($serverUrl) || empty($authEndpointPath)) {
      $this->messenger()->addError($this->t('UserSpice OAuth is not configured correctly. Please contact the site administrator.'));
      return $this->redirect('<front>');
    }

    $state = hash('sha256', uniqid(rand(), TRUE));
    $this->requestStack->getCurrentRequest()->getSession()->set('userspice_oauth_state', $state);

    $params = [
      'response_type' => 'code',
      'client_id' => $clientId,
      'redirect_uri' => $redirectUri,
      'state' => $state,
      'scope' => $scope,
    ];
    $authUrl = $serverUrl . '/' . $authEndpointPath . '?' . http_build_query($params);

    return new TrustedRedirectResponse($authUrl);
  }

  /**
   * Handles the callback from UserSpice.
   */
  public function callback() {
    $request = $this->requestStack->getCurrentRequest();
    $session = $request->getSession();
    $code = $request->query->get('code');
    $receivedState = $request->query->get('state');
    $storedState = $session->get('userspice_oauth_state');
    $session->remove('userspice_oauth_state'); // Clear state after use

    if (empty($storedState) || $receivedState !== $storedState) {
      $this->messenger()->addError($this->t('Invalid OAuth state. CSRF attempt suspected or session expired.'));
      return $this->redirect('<front>');
    }

    if (empty($code)) {
      $error = $request->query->get('error_description') ?: $request->query->get('error') ?: $this->t('Unknown error during UserSpice authentication.');
      $this->messenger()->addError($this->t('UserSpice authentication failed: @error', ['@error' => $error]));
      return $this->redirect('user.login');
    }

    // Exchange code for token.
    $tokenData = $this->exchangeCodeForToken($code);
    if (!$tokenData || !isset($tokenData['access_token'])) {
      $this->messenger()->addError($this->t('Failed to obtain access token from UserSpice. Details: @details', ['@details' => $tokenData['error_description'] ?? $tokenData['error'] ?? 'Unknown error.']));
      return $this->redirect('user.login');
    }

    // Fetch user info from UserSpice.
    $userInfo = $this->fetchUserSpiceUserInfo($tokenData['access_token']);
    if (!$userInfo || !isset($userInfo['email'])) { // Assuming email is primary identifier
      $this->messenger()->addError($this->t('Failed to fetch user information from UserSpice.'));
      return $this->redirect('user.login');
    }

    // Authenticate or provision Drupal user.
    $this->authenticateOrProvisionDrupalUser($userInfo);

    return $this->redirect('<front>'); // Redirect to front page after successful login/provisioning.
  }

  /**
   * Exchanges authorization code for an access token.
   */
  protected function exchangeCodeForToken($code) {
    $serverUrl = rtrim($this->config->get('userspice_server_url'), '/');
    $tokenEndpointPath = $this->config->get('us_token_endpoint_path');
    $clientId = $this->config->get('client_id');
    $clientSecret = $this->config->get('client_secret');
    $redirectUri = Url::fromRoute('userspice_oauth.callback', [], ['absolute' => TRUE])->toString();
    $tokenUrl = $serverUrl . '/' . $tokenEndpointPath;

    try {
      $response = $this->httpClient->post($tokenUrl, [
        'form_params' => [
          'grant_type' => 'authorization_code',
          'code' => $code,
          'redirect_uri' => $redirectUri,
          'client_id' => $clientId,
          'client_secret' => $clientSecret,
        ],
        'headers' => [
            'Accept' => 'application/json',
        ],
      ]);
      return json_decode((string) $response->getBody(), TRUE);
    }
    catch (RequestException $e) {
      $this->getLogger('userspice_oauth')->error('Token exchange failed: @message. Response: @response', [
        '@message' => $e->getMessage(),
        '@response' => $e->hasResponse() ? (string) $e->getResponse()->getBody() : 'No response body'
      ]);
      $errorBody = $e->hasResponse() ? json_decode((string) $e->getResponse()->getBody(), TRUE) : NULL;
      return ['error' => $errorBody['error'] ?? 'request_exception', 'error_description' => $errorBody['error_description'] ?? $e->getMessage()];
    }
  }

  /**
   * Fetches user information from UserSpice.
   */
  protected function fetchUserSpiceUserInfo($accessToken) {
    $serverUrl = rtrim($this->config->get('userspice_server_url'), '/');
    $userInfoEndpointPath = $this->config->get('us_userinfo_endpoint_path');
    $userInfoUrl = $serverUrl . '/' . $userInfoEndpointPath;

    try {
      // UserSpice simple API often expects token as query param.
      // Check UserSpice OAuth server docs if Bearer token is supported.
      $response = $this->httpClient->get($userInfoUrl, [
        'query' => ['access_token' => $accessToken], // Or use Bearer token if supported
        // 'headers' => ['Authorization' => 'Bearer ' . $accessToken],
        'headers' => ['Accept' => 'application/json'],
      ]);
      return json_decode((string) $response->getBody(), TRUE);
    }
    catch (RequestException $e) {
      $this->getLogger('userspice_oauth')->error('User info fetch failed: @message. Response: @response', [
          '@message' => $e->getMessage(),
          '@response' => $e->hasResponse() ? (string) $e->getResponse()->getBody() : 'No response body'
      ]);
      return NULL;
    }
  }

  /**
   * Authenticates or provisions a Drupal user.
   * UserSpice default API returns: id, username, email, fname, lname, etc.
   */
  protected function authenticateOrProvisionDrupalUser(array $userInfo) {
    $usEmail = $userInfo['email'] ?? NULL;
    $usUsername = $userInfo['username'] ?? NULL; // UserSpice username
    $usId = $userInfo['id'] ?? NULL; // UserSpice user ID

    if (empty($usEmail)) {
      $this->messenger()->addError($this->t('UserSpice did not provide an email address. Cannot log in or create account.'));
      return;
    }

    // Try to load user by email.
    $users = $this->entityTypeManager()->getStorage('user')->loadByProperties(['mail' => $usEmail]);
    $drupalUser = reset($users);

    if ($drupalUser) {
      // User exists. Log them in.
      // Optionally: update user fields if they've changed in UserSpice.
      // Using externalauth module would handle this linking robustly.
      // if ($this->externalAuth) {
      //   $this->externalAuth->login($drupalUser, 'userspice_oauth', $usId, $userInfo);
      // } else {
        user_login_finalize($drupalUser);
      // }
      $this->messenger()->addStatus($this->t('Successfully logged in as @name.', ['@name' => $drupalUser->getAccountName()]));
    }
    else {
      // User does not exist. Create if allowed.
      if (!$this->config->get('create_drupal_user')) {
        $this->messenger()->addError($this->t('Login failed. Your UserSpice account is not associated with an account on this site, and automatic user creation is disabled.'));
        return;
      }

      // Determine Drupal username.
      $drupalUsername = $usUsername;
      // Check if UserSpice username already exists in Drupal.
      $existingByName = $this->entityTypeManager()->getStorage('user')->loadByProperties(['name' => $usUsername]);
      if ($existingByName) {
          // If UserSpice username is taken, create one based on email.
          $drupalUsername = User::getCurrentTime()->getRequestTime() . '_' . $usEmail; // Simple unique name.
          $name_parts = explode('@', $usEmail);
          $drupalUsername = $name_parts[0];
          // Ensure it's truly unique.
          $count = 0;
          $candidate_username = $drupalUsername;
          while (user_load_by_name($candidate_username)) {
            $count++;
            $candidate_username = $drupalUsername . $count;
          }
          $drupalUsername = $candidate_username;
      }

      $language = $this->languageManager()->getCurrentLanguage()->getId();
      $user_data = [
        'name' => $drupalUsername,
        'mail' => $usEmail,
        'pass' => user_password(), // Set a random password.
        'status' => 1,
        'init' => $usEmail,
        'langcode' => $language,
        'preferred_langcode' => $language,
        'preferred_admin_langcode' => $language,
        // Map other fields if available and desired:
        // 'field_first_name' => $userInfo['fname'] ?? '',
        // 'field_last_name' => $userInfo['lname'] ?? '',
      ];

      $drupalUser = User::create($user_data);
      $drupalUser->save();

      // if ($this->externalAuth) {
      //   $this->externalAuth->login($drupalUser, 'userspice_oauth', $usId, $userInfo);
      // } else {
        user_login_finalize($drupalUser);
      // }
      $this->messenger()->addStatus($this->t('Account created for @name and logged in.', ['@name' => $drupalUser->getAccountName()]));
    }
  }
}
