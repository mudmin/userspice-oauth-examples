/**
 * UserSpice OAuth Client Configuration
 *
 * Configure these settings to connect to your UserSpice OAuth server.
 *
 * This is a public client: it has no client secret and proves the token
 * exchange with PKCE (S256) and the redirect URI instead. In the UserSpice
 * admin panel, create the client as Version 1, check "Public client", and add
 * this app's origin (e.g. http://localhost:3000) under Allowed Browser Origins
 * so the browser can call the token and userinfo endpoints.
 *
 * PKCE uses crypto.subtle, which browsers only provide in a secure context
 * (https, or http://localhost during development).
 */

const oauthConfig = {
    // The base URL of your UserSpice OAuth server (include trailing slash)
    serverUrl: 'https://your-oauth-server.com/',

    // Your OAuth client ID (obtained from UserSpice admin panel)
    clientId: 'your_client_id',

    // The URL users will be redirected to after authorization
    // This MUST match exactly what is registered in the OAuth server
    redirectUri: 'http://localhost:3000/oauth_response',

    // OAuth scopes to request (space-separated)
    // Available scopes: profile (includes user data)
    scope: 'profile',
};

/**
 * OAuth Endpoints (automatically derived from serverUrl):
 *
 * Authorization: {serverUrl}users/auth/
 * Token:         {serverUrl}users/auth/  (POST with grant_type=authorization_code)
 * UserInfo:      {serverUrl}users/auth/userinfo.php  (GET with Bearer token)
 */

export default oauthConfig;
