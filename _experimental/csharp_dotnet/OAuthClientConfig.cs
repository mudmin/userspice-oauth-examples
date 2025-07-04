// C# .NET Vanilla OAuth Client Example for UserSpice
// Configuration settings
// Note: In a real web application, these would often be loaded from appsettings.json, environment variables, or other configuration sources.

using System.Collections.Generic;

public static class OAuthClientConfig
{
    public static Dictionary<string, string> GetSettings()
    {
        var settings = new Dictionary<string, string>();
        // IMPORTANT: Replace these with your actual UserSpice OAuth server details
        settings.Add("server_url", "https://your-oauth-server.com/"); // Example: "https://example.com/userspice/"
        settings.Add("client_id", "your_client_id");
        settings.Add("client_secret", "your_client_secret");
        // This should be the exact URI registered with your OAuth server for this client
        settings.Add("redirect_uri", "https://your_app_domain.com/oauth_response_csharp"); // Example: "http://localhost:5000/callback"

        // OAuth Endpoints - typically appended to server_url
        settings.Add("auth_endpoint_path", "usersc/plugins/oauth_server/auth.php"); // Path for authorization
        settings.Add("token_endpoint_path", "usersc/plugins/oauth_server/auth.php"); // Path for token exchange (often same as auth for UserSpice)

        return settings;
    }
}
