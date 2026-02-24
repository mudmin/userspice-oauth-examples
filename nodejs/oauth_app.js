/**
 * UserSpice OAuth Client - Node.js Example
 *
 * This is a Node.js/Express implementation of an OAuth 2.0 client for UserSpice.
 * It demonstrates the complete authorization code flow including:
 * - CSRF protection via state parameter
 * - Token exchange
 * - UserInfo endpoint fetching
 * - HMAC signature verification for response data
 *
 * Usage:
 *   npm install express express-session axios
 *   node oauth_app.js
 *   Then visit http://localhost:3000/oauth_request in your browser
 */

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const crypto = require('crypto');
const querystring = require('querystring');
const config = require('./oauth_config');

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true in production with HTTPS
}));

/**
 * Initiates the OAuth flow by redirecting to the authorization server
 */
app.get('/oauth_request', (req, res) => {
    // Generate a random state for CSRF protection
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauth_state = state;

    // Build authorization URL
    const authParams = querystring.stringify({
        response_type: 'code',
        client_id: config.client_id,
        redirect_uri: config.redirect_uri,
        state: state,
        scope: config.scope
    });

    const authUrl = `${config.server_url}users/auth/?${authParams}`;
    res.redirect(authUrl);
});

/**
 * Handles the OAuth callback after user authorization
 */
app.get('/oauth_response', async (req, res) => {
    const { code, state, response: responseParam, signature, error, error_description } = req.query;

    // Check for OAuth errors
    if (error) {
        return res.status(400).send(renderError(`OAuth Error: ${error} - ${error_description || 'No description'}`));
    }

    // Verify required parameters
    if (!code || !state) {
        return res.status(400).send(renderError('Missing authorization code or state parameter'));
    }

    // Verify state to prevent CSRF attacks
    if (state !== req.session.oauth_state) {
        return res.status(400).send(renderError('Invalid state parameter. Possible CSRF attack.'));
    }

    // Clear state (one-time use)
    delete req.session.oauth_state;

    try {
        // Exchange code for access token
        const tokenData = await exchangeCodeForToken(code);

        const accessToken = tokenData.access_token;
        const tokenType = tokenData.token_type || 'Bearer';
        const expiresIn = tokenData.expires_in || 3600;

        // Fetch user info from /userinfo endpoint
        let userInfo = null;
        let userInfoError = null;
        try {
            userInfo = await fetchUserInfo(accessToken);
        } catch (err) {
            userInfoError = err.message;
        }

        // Process response data (UserSpice specific)
        let responseData = null;
        let signatureStatus = 'none'; // 'none', 'verified', 'unverified'

        if (responseParam) {
            const decodedResponse = Buffer.from(responseParam, 'base64').toString('utf8');

            // Verify HMAC signature if response_secret is configured
            if (config.response_secret) {
                if (!signature) {
                    return res.status(400).send(renderError('Response signature missing but response_secret is configured. Possible tampering.'));
                }

                const expectedSignature = crypto
                    .createHmac('sha256', config.response_secret)
                    .update(decodedResponse)
                    .digest('hex');

                // Timing-safe comparison
                if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature))) {
                    return res.status(400).send(renderError('Invalid response signature. Possible tampering detected.'));
                }
                signatureStatus = 'verified';
            } else if (signature) {
                signatureStatus = 'unverified'; // Signature provided but no secret to verify
            }

            try {
                responseData = JSON.parse(decodedResponse);
            } catch (err) {
                return res.status(400).send(renderError(`Failed to parse response data: ${err.message}`));
            }
        }

        // Render success page
        res.send(renderSuccess(accessToken, tokenType, expiresIn, tokenData, userInfo, userInfoError, responseData, signatureStatus));

    } catch (err) {
        res.status(400).send(renderError(`Token exchange failed: ${err.message}`));
    }
});

/**
 * Exchange the authorization code for an access token
 */
async function exchangeCodeForToken(authCode) {
    const tokenUrl = `${config.server_url}users/auth/`;

    const data = {
        grant_type: 'authorization_code',
        code: authCode,
        redirect_uri: config.redirect_uri,
        client_id: config.client_id,
        client_secret: config.client_secret
    };

    const response = await axios.post(tokenUrl, querystring.stringify(data), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    if (response.status !== 200) {
        throw new Error(`HTTP ${response.status}: ${JSON.stringify(response.data)}`);
    }

    return response.data;
}

/**
 * Fetch user information from the OAuth server's userinfo endpoint
 */
async function fetchUserInfo(accessToken) {
    const userInfoUrl = `${config.server_url}users/auth/userinfo`;

    const response = await axios.get(userInfoUrl, {
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/json'
        }
    });

    if (response.status !== 200) {
        throw new Error(`HTTP ${response.status}: ${JSON.stringify(response.data)}`);
    }

    return response.data;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Render error page
 */
function renderError(message) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Error</title>
    <style>${cssStyles}</style>
</head>
<body>
    <h1 class="error">OAuth Error</h1>
    <div class="error-box">${escapeHtml(message)}</div>
    <p><a href="/oauth_request">Try again</a></p>
</body>
</html>`;
}

/**
 * Render success page
 */
function renderSuccess(accessToken, tokenType, expiresIn, tokenData, userInfo, userInfoError, responseData, signatureStatus) {
    let userInfoHtml;
    if (userInfoError) {
        userInfoHtml = `<div class="warning"><p>Could not fetch user info: ${escapeHtml(userInfoError)}</p></div>`;
    } else {
        userInfoHtml = `<pre>${escapeHtml(JSON.stringify(userInfo, null, 2))}</pre>`;
    }

    let responseHtml = '';
    if (responseData) {
        let sigHtml;
        switch (signatureStatus) {
            case 'verified':
                sigHtml = '<p class="signature-verified">HMAC Signature: Verified</p>';
                break;
            case 'unverified':
                sigHtml = `<div class="warning">
                    <p class="signature-warning">HMAC Signature: Not Verified (no response_secret configured)</p>
                    <p>The server sent a signature but this client has no secret to verify it against.</p>
                </div>`;
                break;
            default:
                sigHtml = '<p class="signature-none">HMAC Signature: None (server did not sign response)</p>';
        }

        responseHtml = `
        <h2>Response Data (UserSpice Specific)</h2>
        ${sigHtml}
        <pre>${escapeHtml(JSON.stringify(responseData, null, 2))}</pre>`;

        // Add user data breakdown if present
        if (responseData.userdata) {
            responseHtml += '<h3>User Data</h3><ul>';
            for (const [key, value] of Object.entries(responseData.userdata)) {
                responseHtml += `<li><strong>${escapeHtml(key)}:</strong> ${escapeHtml(typeof value === 'object' ? JSON.stringify(value) : value)}</li>`;
            }
            responseHtml += '</ul>';
        }
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Authentication Successful</title>
    <style>${cssStyles}</style>
</head>
<body>
    <h1>Authentication Successful!</h1>

    <div class="info-box">
        <strong>Access Token:</strong>
        <div class="token">${escapeHtml(accessToken)}</div>
        <p><strong>Token Type:</strong> ${escapeHtml(tokenType)}</p>
        <p><strong>Expires In:</strong> ${expiresIn} seconds</p>
    </div>

    <h2>User Info from /userinfo Endpoint</h2>
    ${userInfoHtml}

    ${responseHtml}

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
    <pre>${escapeHtml(JSON.stringify(tokenData, null, 2))}</pre>
</body>
</html>`;
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
`;

// Start server
app.listen(port, () => {
    console.log(`UserSpice OAuth Client running at http://localhost:${port}`);
    console.log(`Visit http://localhost:${port}/oauth_request to start the OAuth flow`);
});
