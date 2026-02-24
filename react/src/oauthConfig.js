/**
 * UserSpice OAuth Client Configuration
 *
 * Configure these settings to connect to your UserSpice OAuth server.
 *
 * SECURITY WARNING:
 * This is a frontend-only React demo. In production environments:
 * - NEVER expose client_secret in frontend code
 * - Token exchange should happen on a backend server
 * - HMAC signature verification should happen on a backend server
 * - Consider using a BFF (Backend for Frontend) pattern
 *
 * This configuration is for demonstration purposes only!
 */

const oauthConfig = {
    // The base URL of your UserSpice OAuth server (include trailing slash)
    serverUrl: 'https://your-oauth-server.com/',

    // Your OAuth client ID (obtained from UserSpice admin panel)
    clientId: 'your_client_id',

    // Your OAuth client secret (keep this secure!)
    // WARNING: In production, this should NEVER be in frontend code!
    clientSecret: 'your_client_secret',

    // The URL users will be redirected to after authorization
    // This MUST match exactly what is registered in the OAuth server
    redirectUri: 'http://localhost:3000/oauth_response',

    // OAuth scopes to request (space-separated)
    // Available scopes: profile (includes user data)
    scope: 'profile',

    // HMAC Response Secret (optional but recommended for security)
    // WARNING: In production, signature verification should happen server-side!
    // If set, the OAuth server will sign the response data with HMAC-SHA256
    // and this client will verify the signature to prevent tampering.
    // This must match the 'response_secret' configured for your client in UserSpice.
    // Leave empty to disable signature verification (not recommended for production).
    responseSecret: '',
};

/**
 * OAuth Endpoints (automatically derived from serverUrl):
 *
 * Authorization: {serverUrl}users/auth/
 * Token:         {serverUrl}users/auth/  (POST with grant_type=authorization_code)
 * UserInfo:      {serverUrl}users/auth/userinfo  (GET with Bearer token)
 */

export default oauthConfig;
