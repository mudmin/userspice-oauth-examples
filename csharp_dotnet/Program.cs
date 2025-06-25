// C# .NET Vanilla OAuth Client Example for UserSpice
// Main program to simulate OAuth flow

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web; // For HttpUtility

class Program
{
    private static readonly HttpClient httpClient = new HttpClient();

    static async Task Main(string[] args)
    {
        var settings = OAuthClientConfig.GetSettings();

        // --- Simulate Authorization Request ---
        Console.WriteLine("--- OAuth Authorization Request Simulation ---");
        string authorizationEndpoint = settings["server_url"] + settings["auth_endpoint_path"];

        // Generate a random state parameter for CSRF protection
        string state = Guid.NewGuid().ToString();
        // In a real web app, you would store this 'state' in the user's session/cookie.
        Console.WriteLine($"Generated state (should be stored securely, e.g., in session/cookie): {state}");

        var authQueryParams = HttpUtility.ParseQueryString(string.Empty);
        authQueryParams["response_type"] = "code";
        authQueryParams["client_id"] = settings["client_id"];
        authQueryParams["redirect_uri"] = settings["redirect_uri"];
        authQueryParams["state"] = state;
        authQueryParams["scope"] = "profile"; // Add any scopes you need

        string authUrl = authorizationEndpoint + "?" + authQueryParams.ToString();

        Console.WriteLine("\nIn a real web application, you would redirect the user to the following URL:");
        Console.WriteLine(authUrl);
        Console.WriteLine($"\nAfter the user authorizes, they will be redirected to your redirect_uri ('{settings["redirect_uri"]}') with a 'code' and 'state' parameter.");
        Console.WriteLine($"Example: {settings["redirect_uri"]}?code=AUTHORIZATION_CODE_HERE&state={state}");

        // --- Simulate Handling the Response and Token Exchange ---
        Console.WriteLine("\n--- OAuth Token Exchange Simulation ---");
        Console.Write("Enter the 'code' received from UserSpice: ");
        string authCode = Console.ReadLine();

        Console.Write($"Enter the 'state' received from UserSpice (must match '{state}'): ");
        string receivedState = Console.ReadLine();

        if (string.IsNullOrEmpty(authCode))
        {
            Console.Error.WriteLine("Error: No authorization code received.");
            return;
        }

        // IMPORTANT: In a real app, retrieve the original state from where it was stored (e.g., session)
        // For this console app, we compare with the 'state' variable generated above.
        if (string.IsNullOrEmpty(receivedState) || receivedState != state)
        {
            Console.Error.WriteLine($"Error: Invalid state parameter. CSRF attack suspected or state mismatch. Received: '{receivedState}', Expected: '{state}'");
            return;
        }
        Console.WriteLine("State verified successfully.");

        // Exchange the authorization code for an access token
        string tokenEndpoint = settings["server_url"] + settings["token_endpoint_path"];

        var tokenRequestData = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", authCode),
            new KeyValuePair<string, string>("redirect_uri", settings["redirect_uri"]),
            new KeyValuePair<string, string>("client_id", settings["client_id"]),
            new KeyValuePair<string, string>("client_secret", settings["client_secret"])
        });

        try
        {
            HttpResponseMessage response = await httpClient.PostAsync(tokenEndpoint, tokenRequestData);
            string responseBody = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"\nToken Exchange Response (HTTP {(int)response.StatusCode}):");
            Console.WriteLine(responseBody);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("\nAuthentication successful!");
                // Typically, the response is JSON. You would parse it here.
                // Example using System.Text.Json:
                // using var jsonDoc = JsonDocument.Parse(responseBody);
                // string accessToken = jsonDoc.RootElement.GetProperty("access_token").GetString();
                // Console.WriteLine($"Access Token: {accessToken}");
                Console.WriteLine("\nYour login function here. You can now use the access token to make authenticated requests to UserSpice API.");
            }
            else
            {
                Console.Error.WriteLine("Failed to exchange code for token.");
            }
        }
        catch (HttpRequestException e)
        {
            Console.Error.WriteLine($"Error during token exchange: {e.Message}");
        }
        catch (Exception e) // Catch other potential errors like JSON parsing if implemented
        {
            Console.Error.WriteLine($"An unexpected error occurred: {e.Message}");
        }
    }
}
