//! UserSpice OAuth Client - Rust/Actix-web Example
//!
//! This is a Rust/Actix-web implementation of an OAuth 2.0 client for UserSpice.
//! It demonstrates the complete authorization code flow including:
//! - CSRF protection via state parameter
//! - Token exchange
//! - UserInfo endpoint fetching
//! - HMAC signature verification for response data
//!
//! Usage:
//!   cargo run
//!   Then visit http://localhost:8080/ in your browser

use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web::{cookie::Key, get, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::env;
use url::Url;
use serde_json::Value;
use base64::{Engine as _, engine::general_purpose};
use html_escape::encode_text;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    oauth_settings: OAuthSettings,
}

#[derive(Clone)]
struct OAuthSettings {
    server_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scope: String,
    response_secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u32>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    response: Option<String>,
    signature: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

const CSS_STYLES: &str = r#"
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }
h1 { color: #28a745; }
h1.error { color: #dc3545; }
h2 { color: #333; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
.token { background: #fff3cd; padding: 10px; border-radius: 5px; word-break: break-all; font-family: monospace; }
.info-box { background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; }
.warning { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
.error-box { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; color: #721c24; }
.signature-verified { color: #28a745; font-weight: bold; }
.signature-warning { color: #856404; font-weight: bold; }
.signature-none { color: #6c757d; }
a { color: #007bff; }
"#;

/// Home page with login link
#[get("/")]
async fn index(data: web::Data<AppState>) -> impl Responder {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UserSpice OAuth Client - Rust</title>
    <style>{}</style>
</head>
<body>
    <h1>UserSpice OAuth Client</h1>
    <div class="info-box">
        <p>This is a Rust/Actix-web implementation of an OAuth 2.0 client for UserSpice.</p>
        <p><a href="/oauth_request">Login with UserSpice OAuth</a></p>
    </div>
    <h2>Configuration</h2>
    <pre>Server URL: {}
Client ID: {}
Redirect URI: {}</pre>
</body>
</html>"#,
        CSS_STYLES,
        encode_text(&data.oauth_settings.server_url),
        encode_text(&data.oauth_settings.client_id),
        encode_text(&data.oauth_settings.redirect_uri)
    );
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// Initiates the OAuth flow by redirecting to the authorization server
#[get("/oauth_request")]
async fn oauth_request(session: Session, data: web::Data<AppState>) -> impl Responder {
    // Generate a random state for CSRF protection
    let state = generate_state();

    // Store state in session
    if let Err(e) = session.insert("oauth_state", &state) {
        return HttpResponse::InternalServerError().body(format!("Session error: {}", e));
    }

    let auth_url = generate_auth_url(&data.oauth_settings, &state);
    HttpResponse::Found()
        .insert_header(("Location", auth_url))
        .finish()
}

/// Handles the OAuth callback after user authorization
#[get("/oauth_response")]
async fn oauth_response(
    session: Session,
    query: web::Query<CallbackQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    // Check for OAuth errors
    if let Some(ref error) = query.error {
        let error_desc = query.error_description.as_deref().unwrap_or("No description");
        return HttpResponse::BadRequest()
            .content_type("text/html")
            .body(render_error(&format!("OAuth Error: {} - {}", error, error_desc)));
    }

    // Verify required parameters
    let code = match &query.code {
        Some(c) => c,
        None => return HttpResponse::BadRequest()
            .content_type("text/html")
            .body(render_error("Missing authorization code")),
    };

    let state = match &query.state {
        Some(s) => s,
        None => return HttpResponse::BadRequest()
            .content_type("text/html")
            .body(render_error("Missing state parameter")),
    };

    // Verify state to prevent CSRF attacks
    let saved_state: Option<String> = session.get("oauth_state").unwrap_or(None);
    if saved_state.as_ref() != Some(state) {
        return HttpResponse::BadRequest()
            .content_type("text/html")
            .body(render_error("Invalid state parameter. Possible CSRF attack."));
    }

    // Clear state (one-time use)
    session.remove("oauth_state");

    // Exchange code for access token
    let token_data = match exchange_code_for_token(code, &data.oauth_settings).await {
        Ok(t) => t,
        Err(e) => return HttpResponse::BadRequest()
            .content_type("text/html")
            .body(render_error(&format!("Token exchange failed: {}", e))),
    };

    let access_token = &token_data.access_token;
    let token_type = token_data.token_type.as_deref().unwrap_or("Bearer");
    let expires_in = token_data.expires_in.unwrap_or(3600);

    // Fetch user info from /userinfo endpoint
    let (user_info, user_info_error) = match fetch_user_info(access_token, &data.oauth_settings).await {
        Ok(info) => (Some(info), None),
        Err(e) => (None, Some(e.to_string())),
    };

    // Process response data (UserSpice specific)
    let mut response_data: Option<Value> = None;
    let mut signature_status = "none";

    if let Some(ref response_param) = query.response {
        let decoded_bytes = match general_purpose::STANDARD.decode(response_param) {
            Ok(b) => b,
            Err(e) => return HttpResponse::BadRequest()
                .content_type("text/html")
                .body(render_error(&format!("Failed to decode response data: {}", e))),
        };

        let decoded_response = match String::from_utf8(decoded_bytes.clone()) {
            Ok(s) => s,
            Err(e) => return HttpResponse::BadRequest()
                .content_type("text/html")
                .body(render_error(&format!("Invalid UTF-8 in response data: {}", e))),
        };

        // Verify HMAC signature if response_secret is configured
        let response_secret = &data.oauth_settings.response_secret;
        if !response_secret.is_empty() {
            let signature = match &query.signature {
                Some(s) => s,
                None => return HttpResponse::BadRequest()
                    .content_type("text/html")
                    .body(render_error("Response signature missing but RESPONSE_SECRET is configured. Possible tampering.")),
            };

            let expected_signature = compute_hmac(&decoded_response, response_secret);
            if !constant_time_compare(&expected_signature, signature) {
                return HttpResponse::BadRequest()
                    .content_type("text/html")
                    .body(render_error("Invalid response signature. Possible tampering detected."));
            }
            signature_status = "verified";
        } else if query.signature.is_some() {
            signature_status = "unverified";
        }

        response_data = match serde_json::from_str(&decoded_response) {
            Ok(v) => Some(v),
            Err(e) => return HttpResponse::BadRequest()
                .content_type("text/html")
                .body(render_error(&format!("Failed to parse response data: {}", e))),
        };
    }

    // Render success page
    let html = render_success(
        access_token,
        token_type,
        expires_in,
        &token_data,
        user_info.as_ref(),
        user_info_error.as_deref(),
        response_data.as_ref(),
        signature_status,
    );

    HttpResponse::Ok().content_type("text/html").body(html)
}

fn generate_auth_url(settings: &OAuthSettings, state: &str) -> String {
    let mut url = Url::parse(&format!("{}users/auth/", settings.server_url)).unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &settings.client_id)
        .append_pair("redirect_uri", &settings.redirect_uri)
        .append_pair("state", state)
        .append_pair("scope", &settings.scope);
    url.to_string()
}

fn generate_state() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn compute_hmac(message: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn exchange_code_for_token(
    code: &str,
    settings: &OAuthSettings,
) -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let client = Client::new();
    let token_url = format!("{}users/auth/", settings.server_url);

    let response = client
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &settings.redirect_uri),
            ("client_id", &settings.client_id),
            ("client_secret", &settings.client_secret),
        ])
        .send()
        .await?;

    if response.status().is_success() {
        let token_data: TokenResponse = response.json().await?;
        Ok(token_data)
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(format!("HTTP {}: {}", status, body).into())
    }
}

async fn fetch_user_info(
    access_token: &str,
    settings: &OAuthSettings,
) -> Result<Value, Box<dyn std::error::Error>> {
    let client = Client::new();
    let user_info_url = format!("{}users/auth/userinfo", settings.server_url);

    let response = client
        .get(&user_info_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Accept", "application/json")
        .send()
        .await?;

    if response.status().is_success() {
        let user_info: Value = response.json().await?;
        Ok(user_info)
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(format!("HTTP {}: {}", status, body).into())
    }
}

fn render_error(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Error</title>
    <style>{}</style>
</head>
<body>
    <h1 class="error">OAuth Error</h1>
    <div class="error-box">{}</div>
    <p><a href="/oauth_request">Try again</a></p>
</body>
</html>"#,
        CSS_STYLES,
        encode_text(message)
    )
}

fn render_success(
    access_token: &str,
    token_type: &str,
    expires_in: u32,
    token_data: &TokenResponse,
    user_info: Option<&Value>,
    user_info_error: Option<&str>,
    response_data: Option<&Value>,
    signature_status: &str,
) -> String {
    // User info section
    let user_info_html = match (user_info, user_info_error) {
        (_, Some(err)) => format!(
            r#"<div class="warning"><p>Could not fetch user info: {}</p></div>"#,
            encode_text(err)
        ),
        (Some(info), _) => format!(
            "<pre>{}</pre>",
            encode_text(&serde_json::to_string_pretty(info).unwrap_or_default())
        ),
        _ => r#"<div class="warning"><p>No user info available</p></div>"#.to_string(),
    };

    // Response data section
    let response_html = if let Some(data) = response_data {
        let sig_html = match signature_status {
            "verified" => r#"<p class="signature-verified">HMAC Signature: Verified</p>"#.to_string(),
            "unverified" => r#"<div class="warning">
                <p class="signature-warning">HMAC Signature: Not Verified (no RESPONSE_SECRET configured)</p>
                <p>The server sent a signature but this client has no secret to verify it against.</p>
            </div>"#.to_string(),
            _ => r#"<p class="signature-none">HMAC Signature: None (server did not sign response)</p>"#.to_string(),
        };

        let mut html = format!(
            r#"<h2>Response Data (UserSpice Specific)</h2>
            {}
            <pre>{}</pre>"#,
            sig_html,
            encode_text(&serde_json::to_string_pretty(data).unwrap_or_default())
        );

        // Add user data breakdown if present
        if let Some(userdata) = data.get("userdata").and_then(|v| v.as_object()) {
            html.push_str("<h3>User Data</h3><ul>");
            for (key, value) in userdata {
                let display_value = match value {
                    Value::String(s) => s.clone(),
                    _ => value.to_string(),
                };
                html.push_str(&format!(
                    "<li><strong>{}:</strong> {}</li>",
                    encode_text(key),
                    encode_text(&display_value)
                ));
            }
            html.push_str("</ul>");
        }

        html
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Authentication Successful</title>
    <style>{}</style>
</head>
<body>
    <h1>Authentication Successful!</h1>

    <div class="info-box">
        <strong>Access Token:</strong>
        <div class="token">{}</div>
        <p><strong>Token Type:</strong> {}</p>
        <p><strong>Expires In:</strong> {} seconds</p>
    </div>

    <h2>User Info from /userinfo Endpoint</h2>
    {}

    {}

    <h2>Next Steps</h2>
    <div class="warning">
        <p>In a production application, you would now:</p>
        <ol>
            <li>Look up the user in your database by their email or sub (user ID)</li>
            <li>Create a new user account if they don't exist</li>
            <li>Log the user into your application session</li>
            <li>Optionally store the access token for future API calls</li>
        </ol>
    </div>

    <h2>Raw Token Response</h2>
    <pre>{}</pre>
</body>
</html>"#,
        CSS_STYLES,
        encode_text(access_token),
        encode_text(token_type),
        expires_in,
        user_info_html,
        response_html,
        encode_text(&serde_json::to_string_pretty(token_data).unwrap_or_default())
    )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let oauth_settings = OAuthSettings {
        server_url: env::var("SERVER_URL").expect("SERVER_URL must be set"),
        client_id: env::var("CLIENT_ID").expect("CLIENT_ID must be set"),
        client_secret: env::var("CLIENT_SECRET").expect("CLIENT_SECRET must be set"),
        redirect_uri: env::var("REDIRECT_URI").expect("REDIRECT_URI must be set"),
        scope: env::var("SCOPE").unwrap_or_else(|_| "profile".to_string()),
        response_secret: env::var("RESPONSE_SECRET").unwrap_or_default(),
    };

    let app_state = web::Data::new(AppState { oauth_settings });
    let secret_key = Key::generate();

    println!("UserSpice OAuth Client running at http://localhost:8080");
    println!("Visit http://localhost:8080/ to start the OAuth flow");

    HttpServer::new(move || {
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false) // Set to true in production with HTTPS
                    .build()
            )
            .app_data(app_state.clone())
            .service(index)
            .service(oauth_request)
            .service(oauth_response)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
