package main

// UserSpice OAuth Client Configuration
//
// Configure these settings to connect to your UserSpice OAuth server.
//
// To get your client credentials:
// 1. Log into your UserSpice admin panel
// 2. Navigate to OAuth Server settings
// 3. Create a new OAuth client application
// 4. Copy the client_id and client_secret
// 5. Set the redirect_uri to match exactly what you register

var oauthConfig = OAuthConfig{
	// The base URL of your UserSpice OAuth server (include trailing slash)
	ServerURL: "https://your-oauth-server.com/",

	// Your OAuth client ID (obtained from UserSpice admin panel)
	ClientID: "your_client_id",

	// Your OAuth client secret (keep this secure!)
	ClientSecret: "your_client_secret",

	// The URL users will be redirected to after authorization
	// This MUST match exactly what is registered in the OAuth server
	RedirectURI: "http://localhost:8080/oauth_response",

	// OAuth scopes to request (space-separated)
	// Available scopes: profile (includes user data)
	Scope: "profile",

	// HMAC Response Secret (optional but recommended for security)
	// If set, the OAuth server will sign the response data with HMAC-SHA256
	// and this client will verify the signature to prevent tampering.
	// This must match the 'response_secret' configured for your client in UserSpice.
	// Leave empty to disable signature verification.
	ResponseSecret: "",
}

// OAuthConfig holds the OAuth client configuration
type OAuthConfig struct {
	ServerURL      string
	ClientID       string
	ClientSecret   string
	RedirectURI    string
	Scope          string
	ResponseSecret string
}

// OAuth Endpoints (automatically derived from ServerURL):
//
// Authorization: {ServerURL}users/auth/
// Token:         {ServerURL}users/auth/
// UserInfo:      {ServerURL}users/auth/userinfo
