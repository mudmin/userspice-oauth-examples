use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;
use serde_json::Value;
use base64::{Engine as _, engine::general_purpose};

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
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    expires_in: u32,
    // Add any other fields that might be in the token response
}

#[get("/")]
async fn index(data: web::Data<AppState>) -> impl Responder {
    let auth_url = generate_auth_url(&data.oauth_settings);
    HttpResponse::Ok().body(format!(
        "<h1>Rust OAuth Client</h1><p><a href='{}'>Login with OAuth</a></p>",
        auth_url
    ))
}

#[get("/oauth_response")]
async fn oauth_response(query: web::Query<CallbackQuery>, data: web::Data<AppState>) -> impl Responder {
    match exchange_code_for_token(&query.code, &data.oauth_settings).await {
        Ok(token_data) => {
            let response_data = query.response.as_ref()
                .and_then(|r| general_purpose::STANDARD.decode(r).ok())
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .and_then(|json_str| serde_json::from_str::<Value>(&json_str).ok());

            let html = format!(
                r#"
                <h1>Authentication successful!</h1>
                <p>Access Token: {}</p>
                <p>Expires In: {} seconds</p>
                
                <h2>Token Data:</h2>
                <pre>{}</pre>
                
                <h2>Response Data:</h2>
                <pre>{}</pre>
                
                <p>Your login function here. You can now use the access token to make authenticated requests.</p>
                "#,
                token_data.access_token,
                token_data.expires_in,
                serde_json::to_string_pretty(&token_data).unwrap_or_else(|_| "Failed to format token data".to_string()),
                response_data.map_or_else(
                    || "No response data available".to_string(),
                    |v| serde_json::to_string_pretty(&v).unwrap_or_else(|_| "Failed to format response data".to_string())
                )
            );

            HttpResponse::Ok().content_type("text/html").body(html)
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    response: Option<String>,
    // Add state if you're using it
    // state: String,
}

fn generate_auth_url(settings: &OAuthSettings) -> String {
    let mut url = Url::parse(&format!("{}usersc/plugins/oauth_server/auth.php", settings.server_url)).unwrap();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &settings.client_id)
        .append_pair("redirect_uri", &settings.redirect_uri)
        .append_pair("state", &generate_state())
        .append_pair("scope", "profile");
    url.to_string()
}

fn generate_state() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

async fn exchange_code_for_token(code: &str, settings: &OAuthSettings) -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let client = Client::new();
    let token_url = format!("{}usersc/plugins/oauth_server/auth.php", settings.server_url);

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
        Err(format!("Error: {}", response.status()).into())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let oauth_settings = OAuthSettings {
        server_url: env::var("SERVER_URL").expect("SERVER_URL must be set"),
        client_id: env::var("CLIENT_ID").expect("CLIENT_ID must be set"),
        client_secret: env::var("CLIENT_SECRET").expect("CLIENT_SECRET must be set"),
        redirect_uri: env::var("REDIRECT_URI").expect("REDIRECT_URI must be set"),
    };

    let app_state = web::Data::new(AppState { oauth_settings });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(index)
            .service(oauth_response)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}