// Unity C# Script for UserSpice OAuth using System Browser and Custom URI Scheme
// Attach this script to a GameObject in your Unity scene.

using UnityEngine;
using UnityEngine.Networking; // For UnityWebRequest
using System;
using System.Collections;
using System.Collections.Generic; // For Dictionary
using System.Text; // For StringBuilder (manual query string if needed)

public class UserSpiceOAuthHandler : MonoBehaviour
{
    // --- Configuration: Set these in the Inspector or via another script ---
    [Header("UserSpice OAuth Settings")]
    public string userSpiceServerUrl = "https://your-userspice-server.com/usersc/"; // Include trailing slash
    public string clientId = "your_client_id";
    public string clientSecret = "your_client_secret_for_auth_code_flow"; // Required for Auth Code flow. PKCE is better for clients.

    public string authEndpointPath = "plugins/oauth_server/auth.php";
    public string tokenEndpointPath = "plugins/oauth_server/auth.php";
    public string userInfoEndpointPath = "plugins/oauth_server/api.php";
    public string scope = "profile email";

    [Header("Custom URI Scheme Settings")]
    public string customUriScheme = "myunitygame"; // e.g., "mycoolgame" - must match OS registration
    public string customUriCallbackPath = "oauth/callback"; // e.g., "oauth/callback" -> myunitygame://oauth/callback

    private string expectedState;
    private string authorizationCode;

    // --- Events for other scripts to subscribe to ---
    public static event Action<string> OnOAuthLoginSuccess; // Passes UserSpice User Info JSON string
    public static event Action<string> OnOAuthLoginFailed;  // Passes error message

    // --- Singleton Instance (Optional, for easy access) ---
    public static UserSpiceOAuthHandler Instance { get; private set; }

    void Awake()
    {
        // Singleton pattern
        if (Instance == null)
        {
            Instance = this;
            DontDestroyOnLoad(gameObject); // Optional: Keep this handler active across scene loads
            Application.deepLinkActivated += OnDeepLinkActivated; // Subscribe to deep link activations
        }
        else if (Instance != this)
        {
            Destroy(gameObject);
        }
    }

    void OnDestroy() {
        if (Instance == this) {
            Application.deepLinkActivated -= OnDeepLinkActivated;
        }
    }


    /// <summary>
    /// Call this method to start the UserSpice OAuth login process.
    /// Typically called from a UI Button click.
    /// </summary>
    public void StartUserSpiceLogin()
    {
        Debug.Log("UserSpice OAuth: Starting login process...");
        expectedState = Guid.NewGuid().ToString("N"); // Generate a secure random state

        string redirectUri = $"{customUriScheme}://{customUriCallbackPath}";

        var queryParams = new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", clientId },
            { "redirect_uri", redirectUri },
            { "state", expectedState },
            { "scope", scope }
        };

        string authorizationUrl = userSpiceServerUrl.TrimEnd('/') + "/" + authEndpointPath.TrimStart('/') + "?" + BuildQueryString(queryParams);

        Debug.Log($"UserSpice OAuth: Opening URL: {authorizationUrl}");
        Application.OpenURL(authorizationUrl); // Opens in system browser
    }

    /// <summary>
    /// Handles app activation via a deep link / custom URI scheme.
    /// </summary>
    /// <param name="url">The URL that activated the app.</param>
    private void OnDeepLinkActivated(string url)
    {
        Debug.Log($"UserSpice OAuth: Deep link activated with URL: {url}");

        // Check if this is our OAuth callback
        string expectedCallbackPrefix = $"{customUriScheme}://{customUriCallbackPath}";
        if (url.StartsWith(expectedCallbackPrefix))
        {
            Uri uri = new Uri(url);
            var queryParams = ParseQueryString(uri.Query);

            string code = queryParams.ContainsKey("code") ? queryParams["code"] : null;
            string receivedState = queryParams.ContainsKey("state") ? queryParams["state"] : null;
            string error = queryParams.ContainsKey("error") ? queryParams["error"] : null;
            string errorDescription = queryParams.ContainsKey("error_description") ? queryParams["error_description"] : null;

            if (!string.IsNullOrEmpty(error))
            {
                string errMsg = $"OAuth Error from UserSpice: {error} - {errorDescription}";
                Debug.LogError(errMsg);
                OnOAuthLoginFailed?.Invoke(errMsg);
                return;
            }

            if (string.IsNullOrEmpty(code)) {
                string errMsg = "OAuth Error: Authorization code missing in callback.";
                Debug.LogError(errMsg);
                OnOAuthLoginFailed?.Invoke(errMsg);
                return;
            }

            if (receivedState != expectedState)
            {
                string errMsg = "OAuth Error: State mismatch. CSRF attack suspected.";
                Debug.LogError(errMsg);
                OnOAuthLoginFailed?.Invoke(errMsg);
                return;
            }

            Debug.Log($"UserSpice OAuth: Code received: {code}. State verified.");
            authorizationCode = code;

            // Start coroutine to exchange code for token
            StartCoroutine(ExchangeCodeAndGetUserInfoCoroutine(authorizationCode));
        }
    }

    private IEnumerator ExchangeCodeAndGetUserInfoCoroutine(string authCode)
    {
        // 1. Exchange Code for Token
        string tokenUrl = userSpiceServerUrl.TrimEnd('/') + "/" + tokenEndpointPath.TrimStart('/');
        string redirectUri = $"{customUriScheme}://{customUriCallbackPath}";

        WWWForm form = new WWWForm();
        form.AddField("grant_type", "authorization_code");
        form.AddField("code", authCode);
        form.AddField("redirect_uri", redirectUri);
        form.AddField("client_id", clientId);
        form.AddField("client_secret", clientSecret); // Required for Authorization Code flow

        using (UnityWebRequest tokenRequest = UnityWebRequest.Post(tokenUrl, form))
        {
            tokenRequest.SetRequestHeader("Accept", "application/json");
            Debug.Log($"UserSpice OAuth: Sending token request to {tokenUrl}");
            yield return tokenRequest.SendWebRequest();

            if (tokenRequest.result == UnityWebRequest.Result.ConnectionError ||
                tokenRequest.result == UnityWebRequest.Result.ProtocolError)
            {
                string errMsg = $"Token Exchange Error: {tokenRequest.error}. Response: {tokenRequest.downloadHandler?.text}";
                Debug.LogError(errMsg);
                OnOAuthLoginFailed?.Invoke(errMsg);
                yield break;
            }

            string tokenResponseJson = tokenRequest.downloadHandler.text;
            Debug.Log($"UserSpice OAuth: Token Response: {tokenResponseJson}");

            TokenResponseData tokenData = JsonUtility.FromJson<TokenResponseData>(tokenResponseJson); // Simple parsing
            if (tokenData == null || string.IsNullOrEmpty(tokenData.access_token))
            {
                string errorDetails = tokenData?.error_description ?? tokenData?.error ?? "Could not parse access token from response.";
                string errMsg = $"Token Exchange Failed: {errorDetails}";
                Debug.LogError(errMsg);
                OnOAuthLoginFailed?.Invoke(errMsg);
                yield break;
            }

            Debug.Log($"UserSpice OAuth: Access Token obtained: {tokenData.access_token.Substring(0, Mathf.Min(tokenData.access_token.Length, 20))}...");

            // 2. Fetch User Info with Access Token
            string userInfoUrl = userSpiceServerUrl.TrimEnd('/') + "/" + userInfoEndpointPath.TrimStart('/');
            // UserSpice simple API often expects token as query param.
            // Or use Bearer token if supported by UserSpice API.
            string userInfoRequestUrl = $"{userInfoUrl}?access_token={Uri.EscapeDataString(tokenData.access_token)}";

            using (UnityWebRequest userInfoRequest = UnityWebRequest.Get(userInfoRequestUrl))
            {
                // If UserSpice API uses Bearer token:
                // userInfoRequest.SetRequestHeader("Authorization", "Bearer " + tokenData.access_token);
                userInfoRequest.SetRequestHeader("Accept", "application/json");

                Debug.Log($"UserSpice OAuth: Sending user info request to {userInfoRequestUrl}");
                yield return userInfoRequest.SendWebRequest();

                if (userInfoRequest.result == UnityWebRequest.Result.ConnectionError ||
                    userInfoRequest.result == UnityWebRequest.Result.ProtocolError)
                {
                    string errMsg = $"User Info Fetch Error: {userInfoRequest.error}. Response: {userInfoRequest.downloadHandler?.text}";
                    Debug.LogError(errMsg);
                    OnOAuthLoginFailed?.Invoke(errMsg);
                    yield break;
                }

                string userInfoJson = userInfoRequest.downloadHandler.text;
                Debug.Log($"UserSpice OAuth: User Info Response: {userInfoJson}");

                // At this point, userInfoJson contains the user data from UserSpice.
                // You would parse this JSON (e.g. using JsonUtility if simple, or Newtonsoft.Json for complex)
                // and then use it to update game state, display user name, etc.
                OnOAuthLoginSuccess?.Invoke(userInfoJson);
            }
        }
    }

    // Helper to build query string (UnityWebRequest.Post with WWWForm handles this for POST)
    // For GET requests, it's useful.
    private string BuildQueryString(Dictionary<string, string> parameters)
    {
        var stringBuilder = new StringBuilder();
        bool first = true;
        foreach (var param in parameters)
        {
            if (!first)
            {
                stringBuilder.Append("&");
            }
            stringBuilder.Append(Uri.EscapeDataString(param.Key));
            stringBuilder.Append("=");
            stringBuilder.Append(Uri.EscapeDataString(param.Value));
            first = false;
        }
        return stringBuilder.ToString();
    }

    // Helper to parse query string (System.Web.HttpUtility not available in Unity by default)
    private Dictionary<string, string> ParseQueryString(string queryString)
    {
        var nvc = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(queryString)) return nvc;

        queryString = queryString.TrimStart('?');
        foreach (string vp in queryString.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (vp.Contains("="))
            {
                string[] pair = vp.Split(new[] { '=' }, 2, StringSplitOptions.None);
                if (pair.Length == 2)
                {
                    nvc[Uri.UnescapeDataString(pair[0])] = Uri.UnescapeDataString(pair[1]);
                }
                else // key with no value
                {
                     nvc[Uri.UnescapeDataString(pair[0])] = string.Empty;
                }
            }
            else // key with no value and no equals sign
            {
                nvc[Uri.UnescapeDataString(vp)] = string.Empty;
            }
        }
        return nvc;
    }

    // --- Helper class for simple JSON parsing of token response ---
    // JsonUtility requires fields to be public and class to be [Serializable]
    // For more complex JSON, consider using Newtonsoft.Json (Json.NET) for Unity package.
    [System.Serializable]
    private class TokenResponseData
    {
        public string access_token;
        public string token_type;
        public int expires_in;
        public string refresh_token; // If UserSpice provides it
        public string scope;
        // For error responses
        public string error;
        public string error_description;
    }
}
```
