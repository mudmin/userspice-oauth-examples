// Dart/Flutter Vanilla OAuth Client Example for UserSpice
// Configuration settings
// In a Flutter app, these might come from a config file, environment variables passed at build time, or a secure store.

class OAuthClientConfig {
  static Map<String, String> getSettings() {
    // IMPORTANT: Replace these with your actual UserSpice OAuth server details
    return {
      'server_url': 'https://your-oauth-server.com/', // Example: "https://example.com/userspice/"
      'client_id': 'your_client_id',
      'client_secret': 'your_client_secret',
      // This should be the exact URI registered with your OAuth server for this client
      // For Flutter mobile apps, custom URI schemes are often used (e.g., 'myapp://oauth/callback')
      // For web, it's a standard HTTPS URL.
      'redirect_uri': 'https://your_app_domain.com/oauth_response_dart', // Example: "com.example.app://callback" for mobile

      // OAuth Endpoints - typically appended to server_url
      'auth_endpoint_path': 'usersc/plugins/oauth_server/auth.php', // Path for authorization
      'token_endpoint_path': 'usersc/plugins/oauth_server/auth.php', // Path for token exchange
    };
  }
}

// To run this file directly for testing config:
// dart lib/oauth_client_config.dart
void main() {
  print("OAuth Client Configuration (Dart):");
  OAuthClientConfig.getSettings().forEach((key, value) {
    print('$key: $value');
  });
}
