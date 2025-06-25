// Kotlin Vanilla OAuth Client Example for UserSpice
// Simulates handling the OAuth response and exchanging code for a token

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

fun main() {
    val settings = OAuthClientConfig.getSettings()

    println("--- OAuth Token Exchange Simulation (Kotlin) ---")

    // Simulate receiving the authorization code and state from the redirect
    print("Enter the 'code' received from UserSpice: ")
    val authCode = readLine()

    print("Enter the 'state' received from UserSpice (must match the one generated in OAuthRequest): ")
    val receivedState = readLine()

    // Simulate retrieving the original state from session. For this example, we'll just prompt for it.
    print("Enter the original 'state' you stored (from OAuthRequest output): ")
    val originalState = readLine()

    if (authCode.isNullOrEmpty()) {
        System.err.println("Error: No authorization code received.")
        return
    }

    if (receivedState.isNullOrEmpty() || receivedState != originalState) {
        System.err.println("Error: Invalid state parameter. CSRF attack suspected or state mismatch.")
        System.err.println("Received: $receivedState, Original: $originalState")
        return
    }
    println("State verified successfully.")

    // Exchange the authorization code for an access token
    val tokenUrlString = settings["server_url"] + settings["token_endpoint_path"]
    try {
        val tokenUrl = URL(tokenUrlString)
        val conn = tokenUrl.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        conn.doOutput = true

        val postData = buildString {
            append("grant_type=authorization_code")
            append("&code=${URLEncoder.encode(authCode, StandardCharsets.UTF_8.name())}")
            append("&redirect_uri=${URLEncoder.encode(settings["redirect_uri"], StandardCharsets.UTF_8.name())}")
            append("&client_id=${URLEncoder.encode(settings["client_id"], StandardCharsets.UTF_8.name())}")
            append("&client_secret=${URLEncoder.encode(settings["client_secret"], StandardCharsets.UTF_8.name())}")
        }

        conn.outputStream.use { os ->
            val input = postData.toByteArray(StandardCharsets.UTF_8)
            os.write(input, 0, input.length)
        }

        val responseCode = conn.responseCode
        val responseBody = StringBuilder()

        val reader = if (responseCode in 200..299) {
            BufferedReader(InputStreamReader(conn.inputStream))
        } else {
            BufferedReader(InputStreamReader(conn.errorStream))
        }

        reader.useLines { lines ->
            lines.forEach { responseBody.append(it) }
        }
        conn.disconnect()

        println("\nToken Exchange Response (HTTP $responseCode):")
        println(responseBody.toString())

        if (responseCode == 200) {
            println("\nAuthentication successful!")
            // Typically, the response is JSON. You would parse it here using a library like Klaxon, Gson, or kotlinx.serialization.
            // Example:
            // val jsonResponse = Klaxon().parse<Map<String, Any>>(responseBody.toString())
            // val accessToken = jsonResponse?.get("access_token") as? String
            // println("Access Token: $accessToken")
            println("\nYour login function here. You can now use the access token to make authenticated requests to UserSpice API.")
        } else {
            System.err.println("Failed to exchange code for token.")
        }

    } catch (e: Exception) {
        System.err.println("Error during token exchange: ${e.message}")
        e.printStackTrace()
    }
}
