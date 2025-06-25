// Kotlin Vanilla OAuth Client Example for UserSpice
// Configuration settings
// Note: In a real web application, these would often be loaded from a properties file or environment variables.

object OAuthClientConfig {
    fun getSettings(): Map<String, String> {
        val settings = HashMap<String, String>()
        // IMPORTANT: Replace these with your actual UserSpice OAuth server details
        settings["server_url"] = "https://your-oauth-server.com/" // Example: "https://example.com/userspice/"
        settings["client_id"] = "your_client_id"
        settings["client_secret"] = "your_client_secret"
        // This should be the exact URI registered with your OAuth server for this client
        settings["redirect_uri"] = "https://your_app_domain.com/oauth_response_kotlin" // Example: "http://localhost:8080/callback"

        // OAuth Endpoints - typically appended to server_url
        settings["auth_endpoint_path"] = "usersc/plugins/oauth_server/auth.php" // Path for authorization
        settings["token_endpoint_path"] = "usersc/plugins/oauth_server/auth.php" // Path for token exchange (often same as auth for UserSpice)

        return settings
    }
}

fun main() {
    // Helper to print out config if run directly
    println("OAuth Client Configuration (Kotlin):")
    OAuthClientConfig.getSettings().forEach { (key, value) ->
        println("$key: $value")
    }
}
