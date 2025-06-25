// Dart/Flutter Vanilla OAuth Client Example for UserSpice
// Simulates handling the OAuth response and exchanging code for a token (Command-line)

import 'dart:io'; // For stdin
import 'dart:convert'; // For jsonDecode
import 'package:http/http.dart' as http;
import 'package:userspice_oauth_client_dart_example/oauth_client_config.dart'; // Relative path to lib

Future<void> main(List<String> arguments) async {
  final settings = OAuthClientConfig.getSettings();

  print("--- OAuth Token Exchange Simulation (Dart) ---");

  // Simulate receiving the authorization code and state from the redirect
  // In a Flutter app, this would come from the deep link/custom URI handler.
  stdout.write("Enter the 'code' received from UserSpice: ");
  final authCode = stdin.readLineSync();

  stdout.write("Enter the 'state' received from UserSpice (must match the one generated in oauth_request.dart): ");
  final receivedState = stdin.readLineSync();

  // Simulate retrieving the original state. In a Flutter app, you'd retrieve this from secure storage or pass it.
  stdout.write("Enter the original 'state' you stored (from oauth_request.dart output): ");
  final originalState = stdin.readLineSync();

  if (authCode == null || authCode.isEmpty) {
    stderr.writeln("Error: No authorization code received.");
    return;
  }

  if (receivedState == null || receivedState.isEmpty || receivedState != originalState) {
    stderr.writeln("Error: Invalid state parameter. CSRF attack suspected or state mismatch.");
    stderr.writeln("Received: '$receivedState', Original: '$originalState'");
    return;
  }
  print("State verified successfully.");

  // Exchange the authorization code for an access token
  final tokenEndpoint = Uri.parse(settings['server_url']! + settings['token_endpoint_path']!);

  final tokenRequestData = {
    'grant_type': 'authorization_code',
    'code': authCode,
    'redirect_uri': settings['redirect_uri']!,
    'client_id': settings['client_id']!,
    'client_secret': settings['client_secret']!,
  };

  try {
    final response = await http.post(
      tokenEndpoint,
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: tokenRequestData,
    );

    print("\nToken Exchange Response (HTTP ${response.statusCode}):");
    print(response.body);

    if (response.statusCode == 200) {
      print("\nAuthentication successful!");
      // Typically, the response is JSON. You would parse it here.
      try {
        final jsonResponse = jsonDecode(response.body) as Map<String, dynamic>;
        final accessToken = jsonResponse['access_token'] as String?;
        if (accessToken != null) {
          print("Access Token: $accessToken");
        } else {
          print("Access token not found in response.");
        }
      } catch (e) {
        print("Could not parse JSON from response: $e");
      }
      print("\nIn a Flutter app, you would now store the token securely and navigate the user to their authenticated screen.");
    } else {
      stderr.writeln("Failed to exchange code for token.");
    }
  } catch (e) {
    stderr.writeln("Error during token exchange: $e");
  }
}
