// C# Desktop WebView OAuth Example for UserSpice (Conceptual)
// Uses WebView2 (Edge Chromium-based) for .NET (WinForms/WPF)
// and a custom URI scheme or localhost redirect for callback.

// --- Namespaces typically needed ---
// For WinForms:
// using System.Windows.Forms;
// using Microsoft.Web.WebView2.WinForms;
// using Microsoft.Web.WebView2.Core;

// For WPF:
// using System.Windows; // For Window, etc.
// using Microsoft.Web.WebView2.Wpf;
// using Microsoft.Web.WebView2.Core;

using System;
using System.Diagnostics; // For Debug.WriteLine
using System.Net.Http;
using System.Text.Json; // For System.Text.Json
using System.Threading.Tasks;
using System.Web; // For HttpUtility (add reference to System.Web.dll or use alternative for .NET Core/5+)
                  // For .NET Core/5+, consider CommunityToolkit.Maui. अब्सट्रैक्शन्स. HttpUtility or manual parsing.

public class UserSpiceOAuthClient
{
    // --- Configuration ---
    // IMPORTANT: Replace with your UserSpice OAuth Server details
    private const string UserSpiceServerUrl = "https://your-userspice-server.com/usersc/"; // Include trailing slash if needed
    private const string ClientId = "your_client_id";
    // For desktop apps, PKCE is preferred. If not using PKCE, client secret is needed for token exchange.
    private const string ClientSecret = "your_client_secret_for_auth_code_flow"; // Keep this secure

    private const string AuthEndpointPath = "plugins/oauth_server/auth.php";
    private const string TokenEndpointPath = "plugins/oauth_server/auth.php"; // Often same for UserSpice
    private const string UserInfoEndpointPath = "plugins/oauth_server/api.php";
    private const string Scope = "profile email";

    // --- Redirect URI ---
    // Option 1: Custom URI Scheme (Recommended for Desktop Apps if possible)
    // This needs to be registered for your application with the OS.
    // Example: "myapp://oauth/callback"
    private const string RedirectUriCustomScheme = "your-custom-app-scheme://callback";

    // Option 2: Localhost HTTP Redirect (Simpler if custom scheme registration is complex for the project)
    // This means your app needs to listen on this port or expect the WebView to navigate here.
    // No separate HTTP server is strictly needed if WebView2 can just intercept the navigation.
    private const string RedirectUriLocalhost = "http://localhost:9090/callback"; // Choose an available port

    // **CHOOSE ONE Redirect URI and ensure it's registered in UserSpice client settings**
    private static string RedirectUri = RedirectUriCustomScheme; // Or RedirectUriLocalhost

    private static string expectedState; // Store the generated state for verification

    // WebView2 control (assuming it's added to your Form/Window, named 'webView2Control')
    // In WinForms: private Microsoft.Web.WebView2.WinForms.WebView2 webView2Control;
    // In WPF:     private Microsoft.Web.WebView2.Wpf.WebView2 webView2Control;

    // Event or Action to signal completion
    public static event Action<string, string> OAuthCodeReceived; // code, error
    public static event Action<JsonElement> UserInfoReceived; // UserInfo JSON

    // This would be called when your "Login with UserSpice" button is clicked
    public static async Task InitiateLogin(Microsoft.Web.WebView2.Wpf.WebView2 webViewInstance) // Or WinForms.WebView2
    {
        if (webViewInstance == null)
        {
            Debug.WriteLine("WebView2 control not initialized.");
            return;
        }

        // Ensure WebView2 Core is initialized
        try
        {
            await webViewInstance.EnsureCoreWebView2Async(null);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"WebView2 initialization failed: {ex.Message}");
            // Show error to user
            return;
        }

        expectedState = Guid.NewGuid().ToString("N"); // Generate a secure random state

        var authUrlBuilder = new UriBuilder(UserSpiceServerUrl.TrimEnd('/') + "/" + AuthEndpointPath.TrimStart('/'));
        var query = HttpUtility.ParseQueryString(string.Empty); // For System.Web
        query["response_type"] = "code";
        query["client_id"] = ClientId;
        query["redirect_uri"] = RedirectUri;
        query["state"] = expectedState;
        query["scope"] = Scope;
        authUrlBuilder.Query = query.ToString();

        Debug.WriteLine($"Navigating WebView2 to: {authUrlBuilder.Uri}");

        // Subscribe to NavigationStarting to intercept the callback
        webViewInstance.CoreWebView2.NavigationStarting += CoreWebView2_NavigationStarting;

        webViewInstance.CoreWebView2.Navigate(authUrlBuilder.Uri.ToString());
    }

    private static void CoreWebView2_NavigationStarting(object sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationStartingEventArgs e)
    {
        Debug.WriteLine($"WebView2 NavigationStarting: {e.Uri}");
        Uri navigationUri = new Uri(e.Uri);

        // Check if the URI is our redirect URI (either custom scheme or localhost)
        bool isRedirectCustomScheme = RedirectUri.StartsWith(navigationUri.Scheme + "://") &&
                                      navigationUri.Host.Equals(new Uri(RedirectUri).Host, StringComparison.OrdinalIgnoreCase) &&
                                      navigationUri.AbsolutePath.Equals(new Uri(RedirectUri).AbsolutePath, StringComparison.OrdinalIgnoreCase);

        bool isRedirectLocalhost = RedirectUri.StartsWith("http://localhost") &&
                                   e.Uri.StartsWith(RedirectUri, StringComparison.OrdinalIgnoreCase);


        if (isRedirectCustomScheme || isRedirectLocalhost)
        {
            e.Cancel = true; // Stop the WebView from actually navigating to this URL

            // Unsubscribe to prevent multiple triggers if something goes wrong
            // ((Microsoft.Web.WebView2.Core.CoreWebView2)sender).NavigationStarting -= CoreWebView2_NavigationStarting;
            // This is tricky as sender is CoreWebView2. The instance needs to be passed or accessed.
            // For simplicity, assume the webViewInstance used in InitiateLogin can be accessed to unsubscribe,
            // or handle this by checking if code already processed.

            var queryParams = HttpUtility.ParseQueryString(navigationUri.Query);
            string code = queryParams["code"];
            string receivedState = queryParams["state"];
            string error = queryParams["error"];
            string errorDescription = queryParams["error_description"];

            if (!string.IsNullOrEmpty(error))
            {
                Debug.WriteLine($"OAuth Error: {error} - {errorDescription}");
                OAuthCodeReceived?.Invoke(null, $"{error}: {errorDescription}");
                return;
            }

            if (string.IsNullOrEmpty(code))
            {
                 Debug.WriteLine("OAuth Error: Authorization code missing in callback.");
                 OAuthCodeReceived?.Invoke(null, "Authorization code missing.");
                 return;
            }

            if (receivedState != expectedState)
            {
                Debug.WriteLine("OAuth Error: State mismatch. CSRF attack suspected.");
                OAuthCodeReceived?.Invoke(null, "State mismatch.");
                return;
            }

            Debug.WriteLine($"OAuth Success: Code received: {code}");
            OAuthCodeReceived?.Invoke(code, null); // Signal that code is received

            // It's good practice to hide or close the WebView after this.
            // e.g., webViewInstance.Visibility = Visibility.Collapsed; (WPF)
            // e.g., webViewInstance.Visible = false; (WinForms)
        }
    }

    public static async Task<JsonElement?> ExchangeCodeAndGetUserInfoAsync(string authorizationCode)
    {
        if (string.IsNullOrEmpty(authorizationCode)) return null;

        string accessToken = await ExchangeCodeForTokenAsync(authorizationCode);
        if (string.IsNullOrEmpty(accessToken)) return null;

        return await FetchUserSpiceUserInfoAsync(accessToken);
    }

    private static async Task<string> ExchangeCodeForTokenAsync(string code)
    {
        Debug.WriteLine("Exchanging authorization code for token...");
        var tokenUrl = UserSpiceServerUrl.TrimEnd('/') + "/" + TokenEndpointPath.TrimStart('/');

        using (var httpClient = new HttpClient())
        {
            var requestData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", RedirectUri),
                new KeyValuePair<string, string>("client_id", ClientId),
                new KeyValuePair<string, string>("client_secret", ClientSecret) // Required for Auth Code flow
            });

            try
            {
                HttpResponseMessage response = await httpClient.PostAsync(tokenUrl, requestData);
                string responseContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var tokenData = JsonDocument.Parse(responseContent).RootElement;
                    string accessToken = tokenData.TryGetProperty("access_token", out JsonElement tokenElement) ? tokenElement.GetString() : null;
                    Debug.WriteLine($"Access Token obtained: {(string.IsNullOrEmpty(accessToken) ? "None" : accessToken.Substring(0, Math.Min(accessToken.Length, 20)) + "...")}");
                    return accessToken;
                }
                else
                {
                    Debug.WriteLine($"Token exchange failed. Status: {response.StatusCode}, Response: {responseContent}");
                    // Parse error from responseContent if available
                    return null;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Token exchange exception: {ex.Message}");
                return null;
            }
        }
    }

    private static async Task<JsonElement?> FetchUserSpiceUserInfoAsync(string accessToken)
    {
        Debug.WriteLine("Fetching user information...");
        var userInfoUrl = UserSpiceServerUrl.TrimEnd('/') + "/" + UserInfoEndpointPath.TrimStart('/');

        using (var httpClient = new HttpClient())
        {
            // UserSpice simple API might expect token as query param.
            // Or, if it supports Bearer token for userinfo:
            // httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            // string requestUrl = userInfoUrl;

            string requestUrl = $"{userInfoUrl}?access_token={HttpUtility.UrlEncode(accessToken)}"; // Query param method

            try
            {
                HttpResponseMessage response = await httpClient.GetAsync(requestUrl);
                string responseContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var userInfo = JsonDocument.Parse(responseContent).RootElement;
                    Debug.WriteLine($"User Info received: {userInfo.ToString()}");
                    UserInfoReceived?.Invoke(userInfo);
                    return userInfo;
                }
                else
                {
                    Debug.WriteLine($"User info fetch failed. Status: {response.StatusCode}, Response: {responseContent}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"User info fetch exception: {ex.Message}");
                return null;
            }
        }
    }
}

// --- Example Usage (Conceptual, e.g., in your Form's Load or Button Click) ---
/*
public partial class MyLoginForm // : Form or Window
{
    private Microsoft.Web.WebView2.WinForms.WebView2 myWebView; // Or .Wpf.WebView2

    public MyLoginForm()
    {
        // InitializeComponent(); // Standard GUI setup
        // myWebView = new Microsoft.Web.WebView2.WinForms.WebView2();
        // ... add myWebView to form controls ...
        // this.Controls.Add(myWebView);
        // ((System.ComponentModel.ISupportInitialize)(this.myWebView)).BeginInit();
        // this.myWebView.CreationProperties = null;
        // this.myWebView.DefaultBackgroundColor = System.Drawing.Color.White;
        // this.myWebView.Location = new System.Drawing.Point(12, 50); // Example
        // this.myWebView.Name = "myWebView";
        // this.myWebView.Size = new System.Drawing.Size(776, 388); // Example
        // this.myWebView.Source = new System.Uri("about:blank", System.UriKind.Absolute);
        // this.myWebView.TabIndex = 1;
        // this.myWebView.ZoomFactor = 1D;
        // ((System.ComponentModel.ISupportInitialize)(this.myWebView)).EndInit();


        UserSpiceOAuthClient.OAuthCodeReceived += async (code, error) => {
            if (!string.IsNullOrEmpty(code))
            {
                // Hide WebView
                // myWebView.Visible = false; // WinForms
                // myWebView.Visibility = System.Windows.Visibility.Collapsed; // WPF

                Debug.WriteLine($"Login button: Code received {code}. Exchanging for token...");
                var userInfo = await UserSpiceOAuthClient.ExchangeCodeAndGetUserInfoAsync(code);
                if (userInfo.HasValue) {
                    Debug.WriteLine("UserSpice Login successful. User data: " + userInfo.Value.ToString());
                    // Proceed with application logic, e.g., close login window, open main app window.
                    // string userEmail = userInfo.Value.TryGetProperty("email", out JsonElement emailEl) ? emailEl.GetString() : "N/A";
                    // MessageBox.Show($"Login successful! Email: {userEmail}");
                    // this.Close(); // Close login form
                } else {
                    Debug.WriteLine("UserSpice Login failed after code exchange.");
                    // MessageBox.Show("Login failed after code exchange.");
                }
            } else {
                Debug.WriteLine($"Login button: OAuth error: {error}");
                // MessageBox.Show($"OAuth Error: {error}");
            }
        };
    }

    private async void LoginButton_Click(object sender, EventArgs e) // Or RoutedEventArgs for WPF
    {
        // Make WebView visible if it was hidden
        // myWebView.Visible = true; // WinForms
        // myWebView.Visibility = System.Windows.Visibility.Visible; // WPF
        await UserSpiceOAuthClient.InitiateLogin(myWebView);
    }
}
*/
```
