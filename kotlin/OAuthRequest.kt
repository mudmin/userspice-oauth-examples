// Kotlin Vanilla OAuth Client Example for UserSpice
// Simulates initiating the OAuth request

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.UUID

fun main() {
    val settings = OAuthClientConfig.getSettings()

    val authorizationEndpoint = settings["server_url"] + settings["auth_endpoint_path"]

    // Generate a random state parameter for CSRF protection
    val state = UUID.randomUUID().toString()
    // In a real web app, you would store this 'state' in the user's session
    // to verify it on callback.
    println("Generated state (should be stored in session): $state")

    try {
        // Build the authorization URL
        val authUrl = buildString {
            append(authorizationEndpoint)
            append("?response_type=code")
            append("&client_id=${URLEncoder.encode(settings["client_id"], StandardCharsets.UTF_8.name())}")
            append("&redirect_uri=${URLEncoder.encode(settings["redirect_uri"], StandardCharsets.UTF_8.name())}")
            append("&state=${URLEncoder.encode(state, StandardCharsets.UTF_8.name())}")
            append("&scope=${URLEncoder.encode("profile", StandardCharsets.UTF_8.name())}") // Add any scopes you need
        }

        println("\n--- OAuth Authorization Request Simulation (Kotlin) ---")
        println("In a real web application, you would redirect the user to the following URL:")
        println(authUrl)
        println("\nAfter the user authorizes, they will be redirected to your redirect_uri with a 'code' and 'state' parameter.")
        println("Example: ${settings["redirect_uri"]}?code=AUTHORIZATION_CODE_HERE&state=$state")

    } catch (e: Exception) {
        System.err.println("Error building authorization URL: ${e.message}")
        e.printStackTrace()
    }
}
