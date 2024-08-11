# oauth_app.py

from flask import Flask, session, redirect, request
import secrets
from urllib.parse import urlencode
import requests
import json
import base64
import pprint
from oauth_config import OAUTH_SETTINGS

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Set a secret key for session management

@app.route('/oauth_request')
def oauth_request():
    # OAuth server authorization endpoint
    auth_endpoint = OAUTH_SETTINGS['server_url'] + 'usersc/plugins/oauth_server/auth.php'

    # Generate a random state parameter for CSRF protection
    state = secrets.token_hex(16)

    # Store the state in the session for later verification
    session['oauth_state'] = state

    # Build the authorization URL
    auth_params = {
        'response_type': 'code',
        'client_id': OAUTH_SETTINGS['client_id'],
        'redirect_uri': OAUTH_SETTINGS['redirect_uri'],
        'state': state,
        'scope': 'profile'  # Add any scopes you need
    }

    auth_url = auth_endpoint + '?' + urlencode(auth_params)

    # Redirect the user to the authorization URL
    return redirect(auth_url)

@app.route('/oauth_response')
def oauth_response():
    # Get the authorization code and state from the query parameters
    auth_code = request.args.get('code')
    state = request.args.get('state')

    # Verify the state to prevent CSRF attacks
    if state != session.get('oauth_state'):
        return 'Invalid state parameter', 400

    # Exchange the authorization code for an access token
    token_url = OAUTH_SETTINGS['server_url'] + 'usersc/plugins/oauth_server/auth.php'
    token_data = exchange_code_for_token(token_url, OAUTH_SETTINGS['client_id'],
                                         OAUTH_SETTINGS['client_secret'], auth_code,
                                         OAUTH_SETTINGS['redirect_uri'])

    if 'error' in token_data:
        return f"Error: {token_data['error']}", 400

    # Authentication successful
    response = f"Authentication successful!<br>"
    response += f"Access Token: {token_data['access_token']}<br>"
    response += f"Expires In: {token_data['expires_in']} seconds<br>"

    response += "<br>Detailed token data:<br>"
    response += f"<pre>{pprint.pformat(token_data, indent=2)}</pre>"

    # Handle the additional response data
    additional_response = request.args.get('response')
    if additional_response:
        try:
            decoded_response = json.loads(base64.b64decode(additional_response))
            response += "<br>Detailed response data:<br>"
            response += f"<pre>{pprint.pformat(decoded_response, indent=2)}</pre>"
        except json.JSONDecodeError:
            response += "<br>Error: Unable to decode additional response data<br>"

    response += "<br>Your login function here. You can now use the access token to make authenticated requests."

    return response

def exchange_code_for_token(token_url, client_id, client_secret, auth_code, redirect_uri):
    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret
    }

    response = requests.post(token_url, data=data)

    if response.status_code != 200:
        return {
            'error': f'Failed to get access token. HTTP Code: {response.status_code}',
            'response': response.text
        }

    return response.json()

if __name__ == '__main__':
    app.run(port=8000, debug=True)