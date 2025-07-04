// Java Vanilla OAuth Client Example for UserSpice
// Simulates handling the OAuth response and exchanging code for a token

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Scanner;

public class OAuthResponse {

    public static void main(String[] args) {
        Map<String, String> settings = OAuthClientConfig.getSettings();

        System.out.println("--- OAuth Token Exchange Simulation ---");

        // Simulate receiving the authorization code and state from the redirect
        // In a real web app, these would come from the query parameters of the request to your redirect_uri
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the 'code' received from UserSpice: ");
        String authCode = scanner.nextLine();

        System.out.print("Enter the 'state' received from UserSpice (must match the one generated in OAuthRequest): ");
        String receivedState = scanner.nextLine();

        // Simulate retrieving the original state from session. For this example, we'll just prompt for it.
        // In a real app: String originalState = session.getAttribute("oauth_state");
        System.out.print("Enter the original 'state' you stored (from OAuthRequest output): ");
        String originalState = scanner.nextLine();

        if (authCode == null || authCode.isEmpty()) {
            System.err.println("Error: No authorization code received.");
            scanner.close();
            return;
        }

        if (receivedState == null || !receivedState.equals(originalState)) {
            System.err.println("Error: Invalid state parameter. CSRF attack suspected or state mismatch.");
            System.err.println("Received: " + receivedState + ", Original: " + originalState);
            scanner.close();
            return;
        }
        scanner.close();
        System.out.println("State verified successfully.");

        // Exchange the authorization code for an access token
        String tokenUrlString = settings.get("server_url") + settings.get("token_endpoint_path");
        try {
            URL tokenUrl = new URL(tokenUrlString);
            HttpURLConnection conn = (HttpURLConnection) tokenUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);

            String postData = "grant_type=authorization_code" +
                    "&code=" + URLEncoder.encode(authCode, StandardCharsets.UTF_8.name()) +
                    "&redirect_uri=" + URLEncoder.encode(settings.get("redirect_uri"), StandardCharsets.UTF_8.name()) +
                    "&client_id=" + URLEncoder.encode(settings.get("client_id"), StandardCharsets.UTF_8.name()) +
                    "&client_secret=" + URLEncoder.encode(settings.get("client_secret"), StandardCharsets.UTF_8.name());

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = postData.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int responseCode = conn.getResponseCode();
            StringBuilder responseBody = new StringBuilder();
            BufferedReader reader;

            if (responseCode >= 200 && responseCode < 300) {
                reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            } else {
                reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            }

            String line;
            while ((line = reader.readLine()) != null) {
                responseBody.append(line);
            }
            reader.close();
            conn.disconnect();

            System.out.println("\nToken Exchange Response (HTTP " + responseCode + "):");
            System.out.println(responseBody.toString());

            if (responseCode == 200) {
                System.out.println("\nAuthentication successful!");
                // Typically, the response is JSON. You would parse it here.
                // Example:
                // JSONObject jsonResponse = new JSONObject(responseBody.toString());
                // String accessToken = jsonResponse.getString("access_token");
                // System.out.println("Access Token: " + accessToken);
                System.out.println("\nYour login function here. You can now use the access token to make authenticated requests to UserSpice API.");
            } else {
                System.err.println("Failed to exchange code for token.");
            }

        } catch (Exception e) {
            System.err.println("Error during token exchange: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
