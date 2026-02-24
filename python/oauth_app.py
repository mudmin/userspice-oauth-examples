"""
UserSpice OAuth Client - Python/Flask Example

This is a Python/Flask implementation of an OAuth 2.0 client for UserSpice.
It demonstrates the complete authorization code flow including:
- CSRF protection via state parameter
- Token exchange
- UserInfo endpoint fetching
- HMAC signature verification for response data

Usage:
    pip install flask requests
    python oauth_app.py
    Then visit http://localhost:8000/oauth_request in your browser
"""

from flask import Flask, session, redirect, request, Response
import secrets
import hmac
import hashlib
from urllib.parse import urlencode
import requests
import json
import base64
from html import escape
from oauth_config import OAUTH_SETTINGS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secret key for session management


@app.route('/oauth_request')
def oauth_request():
    """Initiates the OAuth flow by redirecting to the authorization server"""
    # Generate a random state for CSRF protection
    state = secrets.token_hex(16)
    session['oauth_state'] = state

    # Build authorization URL
    auth_params = {
        'response_type': 'code',
        'client_id': OAUTH_SETTINGS['client_id'],
        'redirect_uri': OAUTH_SETTINGS['redirect_uri'],
        'state': state,
        'scope': OAUTH_SETTINGS['scope']
    }

    auth_url = OAUTH_SETTINGS['server_url'] + 'users/auth/?' + urlencode(auth_params)
    return redirect(auth_url)


@app.route('/oauth_response')
def oauth_response():
    """Handles the OAuth callback after user authorization"""
    # Check for OAuth errors
    error = request.args.get('error')
    if error:
        error_desc = request.args.get('error_description', 'No description')
        return render_error(f"OAuth Error: {error} - {error_desc}"), 400

    auth_code = request.args.get('code')
    state = request.args.get('state')
    response_param = request.args.get('response')
    signature = request.args.get('signature')

    # Verify required parameters
    if not auth_code or not state:
        return render_error('Missing authorization code or state parameter'), 400

    # Verify state to prevent CSRF attacks
    if state != session.get('oauth_state'):
        return render_error('Invalid state parameter. Possible CSRF attack.'), 400

    # Clear state (one-time use)
    session.pop('oauth_state', None)

    # Exchange code for access token
    token_data = exchange_code_for_token(auth_code)
    if 'error' in token_data:
        return render_error(f"Token exchange failed: {token_data['error']}"), 400

    access_token = token_data.get('access_token', '')
    token_type = token_data.get('token_type', 'Bearer')
    expires_in = token_data.get('expires_in', 3600)

    # Fetch user info from /userinfo endpoint
    user_info = None
    user_info_error = None
    try:
        user_info = fetch_user_info(access_token)
        if 'error' in user_info:
            user_info_error = user_info['error']
            user_info = None
    except Exception as e:
        user_info_error = str(e)

    # Process response data (UserSpice specific)
    response_data = None
    signature_status = 'none'  # 'none', 'verified', 'unverified'

    if response_param:
        try:
            decoded_response = base64.b64decode(response_param).decode('utf-8')
        except Exception as e:
            return render_error(f'Failed to decode response data: {e}'), 400

        # Verify HMAC signature if response_secret is configured
        response_secret = OAUTH_SETTINGS.get('response_secret', '')
        if response_secret:
            if not signature:
                return render_error('Response signature missing but response_secret is configured. Possible tampering.'), 400

            expected_signature = hmac.new(
                response_secret.encode('utf-8'),
                decoded_response.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            # Timing-safe comparison
            if not hmac.compare_digest(expected_signature, signature):
                return render_error('Invalid response signature. Possible tampering detected.'), 400

            signature_status = 'verified'
        elif signature:
            signature_status = 'unverified'  # Signature provided but no secret to verify

        try:
            response_data = json.loads(decoded_response)
        except json.JSONDecodeError as e:
            return render_error(f'Failed to parse response data: {e}'), 400

    # Render success page
    return render_success(access_token, token_type, expires_in, token_data, user_info, user_info_error, response_data, signature_status)


def exchange_code_for_token(auth_code):
    """Exchange the authorization code for an access token"""
    token_url = OAUTH_SETTINGS['server_url'] + 'users/auth/'

    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': OAUTH_SETTINGS['redirect_uri'],
        'client_id': OAUTH_SETTINGS['client_id'],
        'client_secret': OAUTH_SETTINGS['client_secret']
    }

    try:
        response = requests.post(token_url, data=data, timeout=30)

        if response.status_code != 200:
            return {
                'error': f'HTTP {response.status_code}: {response.text}'
            }

        return response.json()
    except requests.RequestException as e:
        return {'error': f'Network error: {e}'}
    except json.JSONDecodeError:
        return {'error': 'Invalid JSON response from server'}


def fetch_user_info(access_token):
    """Fetch user information from the OAuth server's userinfo endpoint"""
    user_info_url = OAUTH_SETTINGS['server_url'] + 'users/auth/userinfo'

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }

    try:
        response = requests.get(user_info_url, headers=headers, timeout=30)

        if response.status_code != 200:
            return {'error': f'HTTP {response.status_code}: {response.text}'}

        return response.json()
    except requests.RequestException as e:
        return {'error': f'Network error: {e}'}
    except json.JSONDecodeError:
        return {'error': 'Invalid JSON response from server'}


def render_error(message):
    """Render error page"""
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Error</title>
    <style>{CSS_STYLES}</style>
</head>
<body>
    <h1 class="error">OAuth Error</h1>
    <div class="error-box">{escape(message)}</div>
    <p><a href="/oauth_request">Try again</a></p>
</body>
</html>'''


def render_success(access_token, token_type, expires_in, token_data, user_info, user_info_error, response_data, signature_status):
    """Render success page"""
    # User info section
    if user_info_error:
        user_info_html = f'<div class="warning"><p>Could not fetch user info: {escape(user_info_error)}</p></div>'
    else:
        user_info_html = f'<pre>{escape(json.dumps(user_info, indent=2))}</pre>'

    # Response data section
    response_html = ''
    if response_data:
        if signature_status == 'verified':
            sig_html = '<p class="signature-verified">HMAC Signature: Verified</p>'
        elif signature_status == 'unverified':
            sig_html = '''<div class="warning">
                <p class="signature-warning">HMAC Signature: Not Verified (no response_secret configured)</p>
                <p>The server sent a signature but this client has no secret to verify it against.</p>
            </div>'''
        else:
            sig_html = '<p class="signature-none">HMAC Signature: None (server did not sign response)</p>'

        response_html = f'''
        <h2>Response Data (UserSpice Specific)</h2>
        {sig_html}
        <pre>{escape(json.dumps(response_data, indent=2))}</pre>'''

        # Add user data breakdown if present
        if 'userdata' in response_data:
            response_html += '<h3>User Data</h3><ul>'
            for key, value in response_data['userdata'].items():
                display_value = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
                response_html += f'<li><strong>{escape(key)}:</strong> {escape(display_value)}</li>'
            response_html += '</ul>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Authentication Successful</title>
    <style>{CSS_STYLES}</style>
</head>
<body>
    <h1>Authentication Successful!</h1>

    <div class="info-box">
        <strong>Access Token:</strong>
        <div class="token">{escape(access_token)}</div>
        <p><strong>Token Type:</strong> {escape(token_type)}</p>
        <p><strong>Expires In:</strong> {expires_in} seconds</p>
    </div>

    <h2>User Info from /userinfo Endpoint</h2>
    {user_info_html}

    {response_html}

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
    <pre>{escape(json.dumps(token_data, indent=2))}</pre>
</body>
</html>'''


CSS_STYLES = '''
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
'''


if __name__ == '__main__':
    print("UserSpice OAuth Client running at http://localhost:8000")
    print("Visit http://localhost:8000/oauth_request to start the OAuth flow")
    app.run(port=8000, debug=True)
