// Dart/Flutter Vanilla OAuth Client Example for UserSpice
// Simulates initiating the OAuth request (Command-line)

import 'dart:io'; // For Platform.environment, not strictly needed for URL building
import 'dart:convert'; // For urlEncode
import 'package:userspice_oauth_client_dart_example/oauth_client_config.dart'; // Relative path to lib
import 'package:uuid/uuid.dart'; // For generating state - add `uuid: ^3.0.0` to pubspec.yaml if you run this

void main(List<String> arguments) {
  // If you added uuid to pubspec.yaml and ran `dart pub get`:
  // final state = Uuid().v4();
  // For this example, without forcing pub get, let's use a simpler pseudo-random state:
  final state = DateTime.now().millisecondsSinceEpoch.toString() + '-' + (Platform.localHostname.hashCode % 10000).toString();

  final settings = OAuthClientConfig.getSettings();
  final authorizationEndpoint = settings['server_url']! + settings['auth_endpoint_path']!;

  // In a Flutter app, you'd store this 'state' securely (e.g., using flutter_secure_storage)
  // or pass it through the auth flow to verify on callback.
  print("Generated state (should be stored securely): $state");

  final authParams = {
    'response_type': 'code',
    'client_id': settings['client_id']!,
    'redirect_uri': settings['redirect_uri']!,
    'state': state,
    'scope': 'profile', // Add any scopes you need
  };

  // URI encode parameters
  final queryString = Uri(queryParameters: authParams).query;
  final authUrl = '$authorizationEndpoint?$queryString';

  print("\n--- OAuth Authorization Request Simulation (Dart) ---");
  print("In a Flutter application, you would use a package like 'url_launcher' to open this URL,");
  print("or a webview (e.g., 'flutter_web_auth', 'flutter_appauth') to handle the flow.");
  print("Authorization URL:");
  print(authUrl);
  print("\nAfter the user authorizes, they will be redirected to your redirect_uri ('${settings['redirect_uri']}') with a 'code' and 'state' parameter.");
  print("Example: ${settings['redirect_uri']}?code=AUTHORIZATION_CODE_HERE&state=$state");
  print("For mobile apps using custom schemes, this redirect would be caught by the app.");
}
