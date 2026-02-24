// UserSpice OAuth Client - Go Example
//
// This is a Go implementation of an OAuth 2.0 client for UserSpice.
// It demonstrates the complete authorization code flow including:
// - CSRF protection via state parameter
// - Token exchange
// - UserInfo endpoint fetching
// - HMAC signature verification for response data
//
// Usage:
//   go run main.go oauth_config.go
//   Then visit http://localhost:8080/oauth_request in your browser

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Simple in-memory state store (use a proper session store in production)
var stateStore = struct {
	sync.RWMutex
	states map[string]bool
}{states: make(map[string]bool)}

func main() {
	http.HandleFunc("/oauth_request", oauthRequest)
	http.HandleFunc("/oauth_response", oauthResponse)
	fmt.Println("UserSpice OAuth Client running on http://localhost:8080")
	fmt.Println("Visit http://localhost:8080/oauth_request to start the OAuth flow")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// oauthRequest initiates the OAuth flow by redirecting to the authorization server
func oauthRequest(w http.ResponseWriter, r *http.Request) {
	// Generate a random state for CSRF protection
	state := generateState()

	// Store the state (in production, use a proper session store)
	stateStore.Lock()
	stateStore.states[state] = true
	stateStore.Unlock()

	// Build authorization URL
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", oauthConfig.ClientID)
	authParams.Set("redirect_uri", oauthConfig.RedirectURI)
	authParams.Set("state", state)
	authParams.Set("scope", oauthConfig.Scope)

	authURL := oauthConfig.ServerURL + "users/auth/?" + authParams.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oauthResponse handles the OAuth callback after user authorization
func oauthResponse(w http.ResponseWriter, r *http.Request) {
	// Check for OAuth errors
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		renderError(w, fmt.Sprintf("OAuth Error: %s - %s", errParam, errorDesc))
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	responseParam := r.URL.Query().Get("response")
	signature := r.URL.Query().Get("signature")

	// Verify required parameters
	if code == "" || state == "" {
		renderError(w, "Missing authorization code or state parameter")
		return
	}

	// Verify state to prevent CSRF attacks
	stateStore.Lock()
	valid := stateStore.states[state]
	if valid {
		delete(stateStore.states, state) // One-time use
	}
	stateStore.Unlock()

	if !valid {
		renderError(w, "Invalid state parameter. Possible CSRF attack.")
		return
	}

	// Exchange code for access token
	tokenData, err := exchangeCodeForToken(code)
	if err != nil {
		renderError(w, fmt.Sprintf("Token exchange failed: %s", err.Error()))
		return
	}

	accessToken, _ := tokenData["access_token"].(string)
	tokenType, _ := tokenData["token_type"].(string)
	if tokenType == "" {
		tokenType = "Bearer"
	}
	expiresIn, _ := tokenData["expires_in"].(float64)

	// Fetch user info from /userinfo endpoint
	userInfo, userInfoErr := fetchUserInfo(accessToken)

	// Process response data (UserSpice specific)
	var responseData map[string]interface{}
	signatureStatus := "none" // "none", "verified", "unverified", "failed"

	if responseParam != "" {
		decodedBytes, err := base64.StdEncoding.DecodeString(responseParam)
		if err != nil {
			renderError(w, "Failed to decode response data")
			return
		}
		decodedResponse := string(decodedBytes)

		// Verify HMAC signature if response_secret is configured
		if oauthConfig.ResponseSecret != "" {
			if signature == "" {
				renderError(w, "Response signature missing but ResponseSecret is configured. Possible tampering.")
				return
			}

			expectedSig := computeHMAC(decodedResponse, oauthConfig.ResponseSecret)
			if !hmac.Equal([]byte(expectedSig), []byte(signature)) {
				renderError(w, "Invalid response signature. Possible tampering detected.")
				return
			}
			signatureStatus = "verified"
		} else if signature != "" {
			signatureStatus = "unverified" // Signature provided but no secret to verify
		}

		if err := json.Unmarshal(decodedBytes, &responseData); err != nil {
			renderError(w, fmt.Sprintf("Failed to parse response data: %s", err.Error()))
			return
		}
	}

	// Render success page
	renderSuccess(w, accessToken, tokenType, int(expiresIn), tokenData, userInfo, userInfoErr, responseData, signatureStatus)
}

// exchangeCodeForToken exchanges the authorization code for an access token
func exchangeCodeForToken(authCode string) (map[string]interface{}, error) {
	tokenURL := oauthConfig.ServerURL + "users/auth/"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", oauthConfig.RedirectURI)
	data.Set("client_id", oauthConfig.ClientID)
	data.Set("client_secret", oauthConfig.ClientSecret)

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("network error: %s", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %s", err.Error())
	}

	return result, nil
}

// fetchUserInfo retrieves user information from the OAuth server's userinfo endpoint
func fetchUserInfo(accessToken string) (map[string]interface{}, error) {
	userInfoURL := oauthConfig.ServerURL + "users/auth/userinfo"

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %s", err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %s", err.Error())
	}

	return result, nil
}

// generateState creates a cryptographically secure random state string
func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// computeHMAC calculates the HMAC-SHA256 signature
func computeHMAC(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// prettyJSON formats data as indented JSON
func prettyJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// renderError displays an error page
func renderError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Error</title>
    <style>%s</style>
</head>
<body>
    <h1 class="error">OAuth Error</h1>
    <div class="error-box">%s</div>
    <p><a href="/oauth_request">Try again</a></p>
</body>
</html>`, cssStyles, html.EscapeString(message))
}

// renderSuccess displays the successful authentication page
func renderSuccess(w http.ResponseWriter, accessToken, tokenType string, expiresIn int, tokenData, userInfo map[string]interface{}, userInfoErr error, responseData map[string]interface{}, signatureStatus string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var userInfoHTML string
	if userInfoErr != nil {
		userInfoHTML = fmt.Sprintf(`<div class="warning"><p>Could not fetch user info: %s</p></div>`, html.EscapeString(userInfoErr.Error()))
	} else {
		userInfoHTML = fmt.Sprintf(`<pre>%s</pre>`, html.EscapeString(prettyJSON(userInfo)))
	}

	var responseHTML string
	if responseData != nil {
		var sigHTML string
		switch signatureStatus {
		case "verified":
			sigHTML = `<p class="signature-verified">HMAC Signature: Verified</p>`
		case "unverified":
			sigHTML = `<div class="warning">
                <p class="signature-warning">HMAC Signature: Not Verified (no ResponseSecret configured)</p>
                <p>The server sent a signature but this client has no secret to verify it against.</p>
            </div>`
		default:
			sigHTML = `<p class="signature-none">HMAC Signature: None (server did not sign response)</p>`
		}

		responseHTML = fmt.Sprintf(`
        <h2>Response Data (UserSpice Specific)</h2>
        %s
        <pre>%s</pre>`, sigHTML, html.EscapeString(prettyJSON(responseData)))

		// Add user data breakdown if present
		if userData, ok := responseData["userdata"].(map[string]interface{}); ok {
			responseHTML += `<h3>User Data</h3><ul>`
			for k, v := range userData {
				responseHTML += fmt.Sprintf(`<li><strong>%s:</strong> %v</li>`, html.EscapeString(k), v)
			}
			responseHTML += `</ul>`
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Authentication Successful</title>
    <style>%s</style>
</head>
<body>
    <h1>Authentication Successful!</h1>

    <div class="info-box">
        <strong>Access Token:</strong>
        <div class="token">%s</div>
        <p><strong>Token Type:</strong> %s</p>
        <p><strong>Expires In:</strong> %d seconds</p>
    </div>

    <h2>User Info from /userinfo Endpoint</h2>
    %s

    %s

    <h2>Next Steps</h2>
    <div class="warning">
        <p>In a production application, you would now:</p>
        <ol>
            <li>Look up the user in your database by their email or sub (user ID)</li>
            <li>Create a new user account if they don't exist</li>
            <li>Log the user into your application session</li>
            <li>Optionally store the access token for future API calls</li>
        </ol>
    </div>

    <h2>Raw Token Response</h2>
    <pre>%s</pre>
</body>
</html>`,
		cssStyles,
		html.EscapeString(accessToken),
		html.EscapeString(tokenType),
		expiresIn,
		userInfoHTML,
		responseHTML,
		html.EscapeString(prettyJSON(tokenData)))
}

const cssStyles = `
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }
h1 { color: #28a745; }
h1.error { color: #dc3545; }
h2 { color: #333; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
.token { background: #fff3cd; padding: 10px; border-radius: 5px; word-break: break-all; font-family: monospace; }
.info-box { background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; }
.warning { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
.error-box { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; color: #721c24; }
.signature-verified { color: #28a745; font-weight: bold; }
.signature-warning { color: #856404; font-weight: bold; }
.signature-none { color: #6c757d; }
a { color: #007bff; }
`
