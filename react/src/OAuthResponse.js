import React, { useState, useEffect, useRef } from 'react';
import oauthConfig from './oauthConfig';
import './App.css';

function OAuthResponse() {
    const [status, setStatus] = useState('loading');
    const [tokenData, setTokenData] = useState(null);
    const [userInfo, setUserInfo] = useState(null);
    const [responseData, setResponseData] = useState(null);
    const [error, setError] = useState(null);
    const handled = useRef(false);

    useEffect(() => {
        // The code and verifier are single-use; don't run twice under StrictMode
        if (handled.current) {
            return;
        }
        handled.current = true;
        processOAuthCallback();
    }, []);

    async function processOAuthCallback() {
        try {
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const response = urlParams.get('response');

            // Verify state parameter (CSRF protection)
            const storedState = sessionStorage.getItem('oauth_state');
            const stateTime = sessionStorage.getItem('oauth_state_time');
            const codeVerifier = sessionStorage.getItem('oauth_code_verifier');

            // Clear stored state and verifier
            sessionStorage.removeItem('oauth_state');
            sessionStorage.removeItem('oauth_state_time');
            sessionStorage.removeItem('oauth_code_verifier');

            if (!state || state !== storedState) {
                throw new Error('Invalid state parameter. Possible CSRF attack.');
            }

            // Check if state is expired (10 minutes max)
            if (stateTime && Date.now() - parseInt(stateTime) > 600000) {
                throw new Error('OAuth state expired. Please try again.');
            }

            if (!code) {
                throw new Error('No authorization code received');
            }

            if (!codeVerifier) {
                throw new Error('PKCE code verifier not found. Please start the login again in this tab.');
            }

            // Decode response data (UserSpice-specific). Unsigned for public
            // clients, so it is shown for display only and not used for identity.
            if (response) {
                try {
                    const decodedResponse = JSON.parse(atob(response));
                    setResponseData(decodedResponse);
                } catch (decodeError) {
                    console.error('Error decoding response:', decodeError);
                }
            }

            // Exchange authorization code for access token (PKCE, no client secret)
            const tokenResponse = await fetch(`${oauthConfig.serverUrl}users/auth/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code: code,
                    redirect_uri: oauthConfig.redirectUri,
                    client_id: oauthConfig.clientId,
                    code_verifier: codeVerifier,
                }),
            });

            if (!tokenResponse.ok) {
                const errorText = await tokenResponse.text();
                throw new Error(`Token exchange failed: ${errorText}`);
            }

            const tokens = await tokenResponse.json();
            setTokenData(tokens);

            if (!tokens.access_token) {
                throw new Error('Token response did not include an access token');
            }

            // Fetch the user's identity from the userinfo endpoint
            const userInfoResponse = await fetch(`${oauthConfig.serverUrl}users/auth/userinfo.php`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${tokens.access_token}`,
                },
            });

            if (!userInfoResponse.ok) {
                const errorText = await userInfoResponse.text();
                throw new Error(`Userinfo request failed: ${errorText}`);
            }

            const userData = await userInfoResponse.json();
            setUserInfo(userData);

            setStatus('success');
        } catch (err) {
            console.error('OAuth callback error:', err);
            setError(err.message);
            setStatus('error');
        }
    }

    if (status === 'loading') {
        return (
            <div className="oauth-container">
                <div className="oauth-card">
                    <div className="loading-spinner"></div>
                    <h2>Processing OAuth Response...</h2>
                    <p>Please wait while we complete the authentication.</p>
                </div>
            </div>
        );
    }

    if (status === 'error') {
        return (
            <div className="oauth-container">
                <div className="oauth-card error-card">
                    <h2>Authentication Failed</h2>
                    <p className="error-message">{error}</p>
                    <a href="/" className="oauth-button">Try Again</a>
                </div>
            </div>
        );
    }

    return (
        <div className="oauth-container">
            <div className="oauth-card success-card">
                <h1>Authentication Successful!</h1>

                <div className="data-section">
                    <h3>Access Token</h3>
                    <div className="token-display">
                        <code>{tokenData?.access_token}</code>
                    </div>
                    <div className="token-info">
                        <span><strong>Type:</strong> {tokenData?.token_type || 'Bearer'}</span>
                        <span><strong>Expires:</strong> {tokenData?.expires_in ? `${tokenData.expires_in} seconds` : 'N/A'}</span>
                    </div>
                </div>

                {userInfo && (
                    <div className="data-section">
                        <h3>User Identity (from userinfo.php)</h3>
                        <pre className="json-display">{JSON.stringify(userInfo, null, 2)}</pre>
                    </div>
                )}

                {responseData && (
                    <>
                        <div className="data-section">
                            <h3>User Data (from response parameter, unsigned)</h3>
                            <pre className="json-display">{JSON.stringify(responseData.userdata, null, 2)}</pre>
                            <p className="hint">This data comes from the redirect URL and is not signed
                                for public clients. Display only; use the userinfo claims for identity.</p>
                        </div>

                        {responseData.tags && (
                            <div className="data-section">
                                <h3>Tags (unsigned)</h3>
                                <pre className="json-display">{JSON.stringify(responseData.tags, null, 2)}</pre>
                            </div>
                        )}

                        {responseData.instructions && (
                            <div className="data-section">
                                <h3>Sync Instructions (unsigned)</h3>
                                <pre className="json-display">{JSON.stringify(responseData.instructions, null, 2)}</pre>
                            </div>
                        )}
                    </>
                )}

                <div className="next-steps">
                    <h3>Next Steps</h3>
                    <p>In a real application, you would now:</p>
                    <ol>
                        <li>Check if the user exists in your database (match on the userinfo "sub" claim)</li>
                        <li>Create a new user if they don't exist</li>
                        <li>Update user data from the userinfo claims</li>
                        <li>Create a local session for the user</li>
                        <li>Redirect to your application's dashboard</li>
                    </ol>
                </div>

                <a href="/" className="oauth-button secondary">Back to Home</a>
            </div>
        </div>
    );
}

export default OAuthResponse;
