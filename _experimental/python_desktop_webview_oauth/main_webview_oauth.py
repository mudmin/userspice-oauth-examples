# Python Desktop WebView OAuth Example for UserSpice
# Uses PyQt6 with QWebEngineView and a local HTTP server for callback.

import sys
import threading
import webbrowser # For fallback if GUI can't start or for alternative flow
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# Attempt to import PyQt6 modules. Provide guidance if not found.
try:
    from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage
    from PyQt6.QtCore import QUrl, pyqtSignal
except ImportError:
    print("PyQt6 or PyQtWebEngine is not installed.")
    print("Please install it: pip install PyQt6 PyQt6-WebEngine")
    print("If issues persist, ensure you have a compatible Qt WebEngine backend installed in your OS.")
    sys.exit(1)

import requests # For token exchange and API calls

# --- Configuration ---
# IMPORTANT: Replace with your UserSpice OAuth Server details
USERSPICE_SERVER_URL = "https://your-userspice-server.com/usersc/" # Include trailing slash if needed
CLIENT_ID = "your_client_id"
# CLIENT_SECRET = "your_client_secret" # Not directly used in implicit flow, but needed for auth code flow token exchange
                                     # For desktop apps, PKCE is preferred over storing client secret.
                                     # This example uses Authorization Code flow, so client_secret is needed server-side for token exchange.
CLIENT_SECRET = "your_client_secret_for_auth_code_flow" # Keep this secure

AUTH_ENDPOINT_PATH = "plugins/oauth_server/auth.php"
TOKEN_ENDPOINT_PATH = "plugins/oauth_server/auth.php" # Often same for UserSpice
USERINFO_ENDPOINT_PATH = "plugins/oauth_server/api.php"
SCOPE = "profile email"

# Localhost server for redirect URI
REDIRECT_URI_HOST = "localhost"
REDIRECT_URI_PORT = 8989 # Choose an available port
REDIRECT_URI = f"http://{REDIRECT_URI_HOST}:{REDIRECT_URI_PORT}/callback"

# Global variable to store the authorization code and state (simplified for example)
authorization_code = None
received_state_param = None
expected_state = "random_state_string_12345" # Generate a proper random state in real app

# --- Local HTTP Server for Callback ---
class OAuthCallbackHandler(BaseHTTPRequestHandler):
    # Signal to notify the main Qt app about the received code
    # This is a bit of a hack for cross-thread communication without full Qt signal/slot from server thread
    # A more robust solution might use QTcpServer within Qt or another IPC mechanism.
    # For simplicity, we'll use a global variable and close the server.
    # code_received_signal = pyqtSignal(str, str) # If this class were a QObject

    def do_GET(self):
        global authorization_code, received_state_param

        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)

        if parsed_path.path == "/callback":
            code = query_params.get('code', [None])[0]
            state = query_params.get('state', [None])[0]

            if code:
                authorization_code = code
                received_state_param = state

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Authentication successful!</h1>")
                self.wfile.write(b"<p>You can close this window/tab now.</p></body></html>")

                # Tell the server to stop after handling this request
                # self.server.shutdown() # This needs to be called from another thread
                # For simplicity, we'll stop it from the main thread after this handler returns
                print(f"Callback received: code={code}, state={state}")
                # OAuthCallbackHandler.code_received_signal.emit(code, state) # If using signal
            else:
                error = query_params.get('error', ['Unknown error'])[0]
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(f"<html><body><h1>Error: {error}</h1></body></html>".encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

http_server_thread = None
httpd = None

def start_local_http_server():
    global httpd
    server_address = (REDIRECT_URI_HOST, REDIRECT_URI_PORT)
    httpd = HTTPServer(server_address, OAuthCallbackHandler)
    print(f"Local callback server started on {REDIRECT_URI_HOST}:{REDIRECT_URI_PORT}...")
    httpd.serve_forever() # This blocks until httpd.shutdown() is called

# --- PyQt6 WebView Application ---
class OAuthWebView(QWebEngineView):
    # Signal emitted when the OAuth flow is complete (code received or error)
    oauth_flow_done = pyqtSignal()

    def __init__(self, auth_url):
        super().__init__()
        self.auth_url = auth_url
        self.profile = QWebEngineProfile("storage", self) # Use off-the-record profile for no cache/cookies
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)

        webpage = QWebEnginePage(self.profile, self)
        self.setPage(webpage)

        self.load(QUrl(self.auth_url))
        # No need to monitor urlChanged here, as the local HTTP server handles the final callback.
        # The webview will navigate to localhost, which our server picks up.
        # The user then sees the "success" or "error" page from our local server in the webview.
        # After that, the main application logic can proceed.

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UserSpice OAuth Login")
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QWidget()
        self.layout = QVBoxLayout(self.central_widget)
        self.setCentralWidget(self.central_widget)

        self.auth_url = self._build_auth_url()
        self.webview = OAuthWebView(self.auth_url)
        self.layout.addWidget(self.webview)

        # self.webview.oauth_flow_done.connect(self.on_oauth_flow_done) # If webview emitted a signal

    def _build_auth_url(self):
        global expected_state
        # In a real app, generate a secure random state and store it (e.g., in a member variable)
        # For this example, 'expected_state' is predefined globally.

        auth_url_base = USERSPICE_SERVER_URL.rstrip('/') + '/' + AUTH_ENDPOINT_PATH.lstrip('/')
        params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'state': expected_state,
            'scope': SCOPE
        }
        return auth_url_base + '?' + requests.compat.urlencode(params)

    def closeEvent(self, event):
        # Ensure server is shut down when window closes, if it's still running
        global httpd
        if httpd:
            print("Shutting down local HTTP server from closeEvent...")
            # httpd.shutdown() # This needs to be called from the server's thread.
            # A more graceful way is to set a flag and have the server loop check it,
            # or use QTcpServer which integrates with Qt event loop.
            # For this example, if server is still running, it might need manual stop or process kill.
            # A simple solution is to just stop the server thread.
            if http_server_thread and http_server_thread.is_alive():
                 # This is abrupt, but for an example:
                 # httpd.server_close() # Close the socket
                 # A better way if server_forever is blocking is to call shutdown from another thread.
                 # Or, just exit the app, which will kill the daemon thread.
                 pass
        event.accept()

# --- Main Application Logic ---
def process_oauth_token_and_userinfo(auth_code):
    print("\nExchanging authorization code for token...")
    token_url = USERSPICE_SERVER_URL.rstrip('/') + '/' + TOKEN_ENDPOINT_PATH.lstrip('/')
    payload = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET # Required for Authorization Code flow
    }
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status() # Raise an exception for HTTP errors
        token_data = response.json()
        access_token = token_data.get('access_token')
        print("Access Token obtained:", access_token[:20] + "..." if access_token else "None")

        if access_token:
            print("\nFetching user information...")
            userinfo_url = USERSPICE_SERVER_URL.rstrip('/') + '/' + USERINFO_ENDPOINT_PATH.lstrip('/')
            headers = {'Authorization': f'Bearer {access_token}'}
            # UserSpice simple API might expect token as query param:
            # userinfo_response = requests.get(userinfo_url, params={'access_token': access_token})
            userinfo_response = requests.get(userinfo_url, headers=headers)
            userinfo_response.raise_for_status()
            user_info = userinfo_response.json()
            print("User Info:", user_info)
            # Here, you would use the user_info to update your application's state
            return user_info
        else:
            print("Failed to obtain access token. Response:", token_data)
            return None
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during OAuth token/userinfo exchange: {e}")
        if e.response is not None:
            print(f"Response Body: {e.response.text}")
        return None

def main():
    global http_server_thread, httpd, authorization_code, received_state_param, expected_state

    # Start the local HTTP server in a separate thread
    # It's a daemon thread so it will exit when the main thread exits
    http_server_thread = threading.Thread(target=start_local_http_server, daemon=True)
    http_server_thread.start()

    # Initialize and run the PyQt application
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()

    # Periodically check if the authorization code has been received by the HTTP server
    # This is a polling mechanism, simpler for this example than full cross-thread signals.
    # In a real Qt app, the HTTP server (if also Qt-based like QTcpServer)
    # or a worker QObject could emit a signal.

    # This is a blocking way to wait for the callback, not ideal for GUI responsiveness usually.
    # A timer could be used in Qt to check `authorization_code` without blocking.
    print("Waiting for UserSpice authentication in the browser window...")
    print(f"Please complete login and authorization. App will then attempt to use the code received at {REDIRECT_URI}")

    # For this example, we'll let the Qt event loop run.
    # The user interacts with the WebView. When the callback is hit, `authorization_code` is set.
    # We need a way to trigger the token exchange AFTER the Qt window is possibly closed or flow is done.
    # A simple way for this script: after app.exec() finishes (window closed), check the code.

    app_exit_code = app.exec() # This blocks until the Qt application exits

    print("Qt Application has exited.")

    # Shutdown the HTTP server explicitly if it's still running
    # This is tricky because httpd.serve_forever() blocks its thread.
    # httpd.shutdown() must be called from a different thread.
    # Since the thread is a daemon, it will be killed when main exits.
    # A more graceful shutdown involves httpd.shutdown() being called.
    if httpd:
        print("Attempting to shut down local HTTP server...")
        # This is a common pattern: server runs in a thread, main thread calls shutdown.
        # Need to make sure serve_forever() can be interrupted or shutdown is effective.
        # For HTTPServer, shutdown() sets a flag that serve_forever() checks.
        shutdown_thread = threading.Thread(target=httpd.shutdown)
        shutdown_thread.daemon = True
        shutdown_thread.start()
        # http_server_thread.join(timeout=2) # Wait briefly for server thread to finish

    if authorization_code:
        print(f"\nAuthorization Code received: {authorization_code}")
        if received_state_param == expected_state:
            print("State verified.")
            process_oauth_token_and_userinfo(authorization_code)
        else:
            print(f"State mismatch! Expected: '{expected_state}', Received: '{received_state_param}'")
            print("OAuth flow aborted due to state mismatch.")
    else:
        print("\nOAuth flow was not completed or was cancelled by the user (no authorization code received).")

    sys.exit(app_exit_code)


if __name__ == '__main__':
    # --- Fallback for non-GUI environment or if PyQt fails ---
    # This part is NOT using WebView, but shows the general flow logic
    # that would happen *after* code is obtained from WebView.
    # To test this part directly without GUI, comment out main() call above
    # and uncomment the fallback_main() call below.
    # fallback_main()

    main() # Run the PyQt GUI application

def fallback_main():
    # This is a non-GUI fallback to test the token exchange part if you have a code
    print("Running in non-GUI fallback mode.")
    global expected_state
    auth_url_base = USERSPICE_SERVER_URL.rstrip('/') + '/' + AUTH_ENDPOINT_PATH.lstrip('/')
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI, # User would manually paste this into browser
        'state': expected_state,
        'scope': SCOPE
    }
    manual_auth_url = auth_url_base + '?' + requests.compat.urlencode(params)
    print(f"Please open this URL in your browser:\n{manual_auth_url}")
    print(f"\nAfter authorizing, UserSpice will redirect to a localhost URL like:")
    print(f"{REDIRECT_URI}?code=YOUR_CODE&state={expected_state}")
    print("Copy the 'code' value from that URL.")

    auth_code_manual = input("Enter the authorization code: ").strip()
    received_state_manual = input(f"Enter the state parameter (should be '{expected_state}'): ").strip()

    if auth_code_manual:
        if received_state_manual == expected_state:
            process_oauth_token_and_userinfo(auth_code_manual)
        else:
            print("State mismatch in manual fallback.")
    else:
        print("No authorization code entered in fallback.")
```
