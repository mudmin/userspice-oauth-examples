package main

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/url"
)

var oauthSettings = map[string]string{
    "server_url":    "https://yourserver.com/",
    "client_id":     "your_client_id",
    "client_secret": "your_client_secret",
    "redirect_uri":  "http://localhost:8080/oauth_response",
}

func main() {
    http.HandleFunc("/oauth_request", oauthRequest)
    http.HandleFunc("/oauth_response", oauthResponse)
    fmt.Println("Server is running on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func oauthRequest(w http.ResponseWriter, r *http.Request) {
    state := generateState()
    // In a real application, you'd want to store this state securely, possibly in a database
    // For this example, we'll use a file, but this is not secure for production use
    err := ioutil.WriteFile("state.txt", []byte(state), 0644)
    if err != nil {
        http.Error(w, "Error generating state", http.StatusInternalServerError)
        return
    }

    authParams := url.Values{}
    authParams.Set("response_type", "code")
    authParams.Set("client_id", oauthSettings["client_id"])
    authParams.Set("redirect_uri", oauthSettings["redirect_uri"])
    authParams.Set("state", state)
    authParams.Set("scope", "profile")

    authURL := oauthSettings["server_url"] + "usersc/plugins/oauth_server/auth.php?" + authParams.Encode()
    http.Redirect(w, r, authURL, http.StatusFound)
}

func oauthResponse(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    response := r.URL.Query().Get("response")

    // Verify state
    savedState, err := ioutil.ReadFile("state.txt")
    if err != nil || string(savedState) != state {
        http.Error(w, "Invalid state parameter", http.StatusBadRequest)
        return
    }

    // Exchange code for token
    tokenData, err := exchangeCodeForToken(code)
    if err != nil {
        http.Error(w, "Error exchanging code for token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Create response
    responseHtml := fmt.Sprintf("<h1>Authentication successful!</h1>"+
        "<p>Access Token: %s</p>"+
        "<p>Expires In: %d seconds</p>"+
        "<h2>Detailed token data:</h2>"+
        "<pre>%s</pre>",
        tokenData["access_token"], tokenData["expires_in"], prettyPrint(tokenData))

    if response != "" {
        decodedResponse, _ := base64.StdEncoding.DecodeString(response)
        var responseData map[string]interface{}
        json.Unmarshal(decodedResponse, &responseData)
        responseHtml += fmt.Sprintf("<h2>Detailed response data:</h2><pre>%s</pre>", prettyPrint(responseData))
    }

    responseHtml += "<p>Your login function here. You can now use the access token to make authenticated requests.</p>"

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, responseHtml)
}

func exchangeCodeForToken(authCode string) (map[string]interface{}, error) {
    tokenUrl := oauthSettings["server_url"] + "usersc/plugins/oauth_server/auth.php"
    data := url.Values{}
    data.Set("grant_type", "authorization_code")
    data.Set("code", authCode)
    data.Set("redirect_uri", oauthSettings["redirect_uri"])
    data.Set("client_id", oauthSettings["client_id"])
    data.Set("client_secret", oauthSettings["client_secret"])

    resp, err := http.PostForm(tokenUrl, data)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("failed to get access token. HTTP Code: %d, Body: %s", resp.StatusCode, string(body))
    }

    var result map[string]interface{}
    err = json.Unmarshal(body, &result)
    if err != nil {
        return nil, err
    }

    return result, nil
}

func generateState() string {
    b := make([]byte, 16)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}

func prettyPrint(v interface{}) string {
    b, _ := json.MarshalIndent(v, "", "  ")
    return string(b)
}