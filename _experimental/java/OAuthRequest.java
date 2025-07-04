// Java Vanilla OAuth Client Example for UserSpice
// Simulates initiating the OAuth request

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

public class OAuthRequest {

    public static void main(String[] args) {
        Map<String, String> settings = OAuthClientConfig.getSettings();

        String authorizationEndpoint = settings.get("server_url") + settings.get("auth_endpoint_path");

        // Generate a random state parameter for CSRF protection
        String state = UUID.randomUUID().toString();
        // In a real web app, you would store this 'state' in the user's session
        // to verify it on callback.
        System.out.println("Generated state (should be stored in session): " + state);

        try {
            // Build the authorization URL
            String authUrl = authorizationEndpoint + "?" +
                    "response_type=code" +
                    "&client_id=" + URLEncoder.encode(settings.get("client_id"), StandardCharsets.UTF_8.name()) +
                    "&redirect_uri=" + URLEncoder.encode(settings.get("redirect_uri"), StandardCharsets.UTF_8.name()) +
                    "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8.name()) +
                    "&scope=" + URLEncoder.encode("profile", StandardCharsets.UTF_8.name()); // Add any scopes you need

            System.out.println("\n--- OAuth Authorization Request Simulation ---");
            System.out.println("In a real web application, you would redirect the user to the following URL:");
            System.out.println(authUrl);
            System.out.println("\nAfter the user authorizes, they will be redirected to your redirect_uri with a 'code' and 'state' parameter.");
            System.out.println("Example: " + settings.get("redirect_uri") + "?code=AUTHORIZATION_CODE_HERE&state=" + state);

        } catch (Exception e) {
            System.err.println("Error building authorization URL: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
