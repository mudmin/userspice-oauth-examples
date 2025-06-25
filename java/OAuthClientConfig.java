// Java Vanilla OAuth Client Example for UserSpice
// Configuration settings
// Note: In a real web application, these would often be loaded from a properties file or environment variables.

import java.util.HashMap;
import java.util.Map;

public class OAuthClientConfig {

    public static Map<String, String> getSettings() {
        Map<String, String> settings = new HashMap<>();
        // IMPORTANT: Replace these with your actual UserSpice OAuth server details
        settings.put("server_url", "https://your-oauth-server.com/"); // Example: "https://example.com/userspice/"
        settings.put("client_id", "your_client_id");
        settings.put("client_secret", "your_client_secret");
        // This should be the exact URI registered with your OAuth server for this client
        settings.put("redirect_uri", "https://your_app_domain.com/oauth_response_java"); // Example: "http://localhost:8080/callback"

        // OAuth Endpoints - typically appended to server_url
        settings.put("auth_endpoint_path", "usersc/plugins/oauth_server/auth.php"); // Path for authorization
        settings.put("token_endpoint_path", "usersc/plugins/oauth_server/auth.php"); // Path for token exchange (often same as auth for UserSpice)

        return settings;
    }

    public static void main(String[] args) {
        // Helper to print out config if run directly
        System.out.println("OAuth Client Configuration:");
        for (Map.Entry<String, String> entry : getSettings().entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }
}
