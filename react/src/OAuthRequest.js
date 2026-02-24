import React, { useEffect, useState } from 'react';
import oauthConfig from './oauthConfig';
import './App.css';

/**
 * Generate a cryptographically secure random state parameter
 * Uses Web Crypto API for better security than Math.random()
 */
function generateSecureState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function OAuthRequest() {
    const [redirecting, setRedirecting] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        try {
            // Generate cryptographically secure state parameter for CSRF protection
            const state = generateSecureState();

            // Store state in localStorage (sessionStorage is also acceptable)
            localStorage.setItem('oauth_state', state);
            localStorage.setItem('oauth_state_time', Date.now().toString());

            // Build authorization URL
            const authParams = new URLSearchParams({
                response_type: 'code',
                client_id: oauthConfig.clientId,
                redirect_uri: oauthConfig.redirectUri,
                state: state,
                scope: oauthConfig.scope
            });

            const authUrl = `${oauthConfig.serverUrl}users/auth/?${authParams}`;

            // Redirect to OAuth server
            window.location.href = authUrl;
        } catch (err) {
            setError('Failed to initiate OAuth flow: ' + err.message);
            setRedirecting(false);
        }
    }, []);

    if (error) {
        return (
            <div className="oauth-container">
                <div className="oauth-card error-card">
                    <h2>OAuth Error</h2>
                    <p className="error-message">{error}</p>
                    <a href="/" className="oauth-button">Back to Home</a>
                </div>
            </div>
        );
    }

    return (
        <div className="oauth-container">
            <div className="oauth-card">
                <div className="loading-spinner"></div>
                <h2>Redirecting to OAuth Server...</h2>
                <p>You will be redirected to login with UserSpice OAuth.</p>
                <p className="hint">If you are not redirected automatically,
                    please check your browser's popup blocker.</p>
            </div>
        </div>
    );
}

export default OAuthRequest;
