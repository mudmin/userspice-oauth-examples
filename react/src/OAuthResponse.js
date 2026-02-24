import React, { useState, useEffect } from 'react';
import oauthConfig from './oauthConfig';
import './App.css';

/**
 * Verify HMAC-SHA256 signature of response data
 * Note: In production, this should be done server-side!
 *
 * @param {string} data - The base64-encoded response data
 * @param {string} signature - The hex-encoded HMAC signature
 * @param {string} secret - The shared secret key
 * @returns {Promise<boolean>} - Whether the signature is valid
 */
async function verifySignature(data, signature, secret) {
    if (!secret || !signature) {
        return { valid: false, reason: 'missing' };
    }

    try {
        // Decode base64 response data
        const decodedData = atob(data);

        // Create HMAC-SHA256 key
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret);
        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        // Calculate expected signature
        const messageData = encoder.encode(decodedData);
        const signatureBuffer = await crypto.subtle.sign('HMAC', key, messageData);
        const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');

        // Constant-time comparison (best effort in JavaScript)
        if (expectedSignature.length !== signature.length) {
            return { valid: false, reason: 'invalid' };
        }

        let result = 0;
        for (let i = 0; i < expectedSignature.length; i++) {
            result |= expectedSignature.charCodeAt(i) ^ signature.charCodeAt(i);
        }

        return { valid: result === 0, reason: result === 0 ? 'valid' : 'invalid' };
    } catch (err) {
        console.error('Signature verification error:', err);
        return { valid: false, reason: 'error' };
    }
}

function OAuthResponse() {
    const [status, setStatus] = useState('loading');
    const [tokenData, setTokenData] = useState(null);
    const [userInfo, setUserInfo] = useState(null);
    const [responseData, setResponseData] = useState(null);
    const [signatureStatus, setSignatureStatus] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        processOAuthCallback();
    }, []);

    async function processOAuthCallback() {
        try {
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const response = urlParams.get('response');
            const signature = urlParams.get('signature');

            // Verify state parameter (CSRF protection)
            const storedState = localStorage.getItem('oauth_state');
            const stateTime = localStorage.getItem('oauth_state_time');

            if (!state || state !== storedState) {
                throw new Error('Invalid state parameter. Possible CSRF attack.');
            }

            // Check if state is expired (10 minutes max)
            if (stateTime && Date.now() - parseInt(stateTime) > 600000) {
                throw new Error('OAuth state expired. Please try again.');
            }

            // Clear stored state
            localStorage.removeItem('oauth_state');
            localStorage.removeItem('oauth_state_time');

            if (!code) {
                throw new Error('No authorization code received');
            }

            // Verify HMAC signature if configured
            if (oauthConfig.responseSecret) {
                if (!signature) {
                    throw new Error('Response signature required but not provided');
                }
                const sigResult = await verifySignature(response, signature, oauthConfig.responseSecret);
                if (!sigResult.valid) {
                    throw new Error('Invalid response signature. Data may have been tampered with.');
                }
                setSignatureStatus('verified');
            } else if (signature) {
                setSignatureStatus('unverified');
                console.warn('Response signature provided but no secret configured. Cannot verify.');
            } else {
                setSignatureStatus('none');
            }

            // Decode response data (UserSpice-specific)
            if (response) {
                try {
                    const decodedResponse = JSON.parse(atob(response));
                    setResponseData(decodedResponse);
                } catch (decodeError) {
                    console.error('Error decoding response:', decodeError);
                }
            }

            // Exchange authorization code for access token
            // WARNING: In production, this should happen on a backend server!
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
                    client_secret: oauthConfig.clientSecret,
                }),
            });

            if (!tokenResponse.ok) {
                const errorText = await tokenResponse.text();
                throw new Error(`Token exchange failed: ${errorText}`);
            }

            const tokens = await tokenResponse.json();
            setTokenData(tokens);

            // Fetch user info from /userinfo endpoint
            if (tokens.access_token) {
                const userInfoResponse = await fetch(`${oauthConfig.serverUrl}users/auth/userinfo`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${tokens.access_token}`,
                    },
                });

                if (userInfoResponse.ok) {
                    const userData = await userInfoResponse.json();
                    setUserInfo(userData);
                }
            }

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

                {signatureStatus === 'verified' && (
                    <div className="signature-badge verified">
                        HMAC Signature Verified
                    </div>
                )}
                {signatureStatus === 'unverified' && (
                    <div className="signature-badge warning">
                        Signature Present But Not Verified (no secret configured)
                    </div>
                )}

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
                        <h3>User Info (from /userinfo endpoint)</h3>
                        <pre className="json-display">{JSON.stringify(userInfo, null, 2)}</pre>
                    </div>
                )}

                {responseData && (
                    <>
                        <div className="data-section">
                            <h3>User Data (from response parameter)</h3>
                            <pre className="json-display">{JSON.stringify(responseData.userdata, null, 2)}</pre>
                        </div>

                        {responseData.tags && (
                            <div className="data-section">
                                <h3>Tags</h3>
                                <pre className="json-display">{JSON.stringify(responseData.tags, null, 2)}</pre>
                            </div>
                        )}

                        {responseData.instructions && (
                            <div className="data-section">
                                <h3>Sync Instructions</h3>
                                <pre className="json-display">{JSON.stringify(responseData.instructions, null, 2)}</pre>
                            </div>
                        )}
                    </>
                )}

                <div className="next-steps">
                    <h3>Next Steps</h3>
                    <p>In a real application, you would now:</p>
                    <ol>
                        <li>Check if the user exists in your database</li>
                        <li>Create a new user if they don't exist</li>
                        <li>Update user data based on sync instructions</li>
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
