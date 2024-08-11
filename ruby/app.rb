require 'sinatra'
require 'sinatra/reloader' if development?
require 'httparty'
require 'json'
require 'securerandom'
require 'base64'

OAUTH_SETTINGS = {
  server_url: 'https://your_server.com/',
  client_id: 'your_client_id',
  client_secret: 'your_client_secret',
  redirect_uri: 'http://localhost:4567/oauth_response'
}

enable :sessions
set :session_secret, SecureRandom.hex(64)

get '/oauth_request' do
  state = SecureRandom.hex(16)
  session[:oauth_state] = state

  auth_params = {
    response_type: 'code',
    client_id: OAUTH_SETTINGS[:client_id],
    redirect_uri: OAUTH_SETTINGS[:redirect_uri],
    state: state,
    scope: 'profile'
  }

  auth_url = "#{OAUTH_SETTINGS[:server_url]}usersc/plugins/oauth_server/auth.php?#{URI.encode_www_form(auth_params)}"
  redirect auth_url
end

get '/oauth_response' do
  if params[:state] != session[:oauth_state]
    return 'Invalid state parameter'
  end

  token_data = exchange_code_for_token(params[:code])

  response_html = "<h1>Authentication successful!</h1>"
  response_html << "<p>Access Token: #{token_data['access_token']}</p>"
  response_html << "<p>Expires In: #{token_data['expires_in']} seconds</p>"
  
  response_html << "<h2>Detailed token data:</h2>"
  response_html << "<pre>#{JSON.pretty_generate(token_data)}</pre>"

  if params[:response]
    decoded_response = JSON.parse(Base64.decode64(params[:response]))
    response_html << "<h2>Detailed response data:</h2>"
    response_html << "<pre>#{JSON.pretty_generate(decoded_response)}</pre>"
  end

  response_html << "<p>Your login function here. You can now use the access token to make authenticated requests.</p>"

  response_html
end

def exchange_code_for_token(auth_code)
  token_url = "#{OAUTH_SETTINGS[:server_url]}usersc/plugins/oauth_server/auth.php"
  response = HTTParty.post(token_url, 
    body: {
      grant_type: 'authorization_code',
      code: auth_code,
      redirect_uri: OAUTH_SETTINGS[:redirect_uri],
      client_id: OAUTH_SETTINGS[:client_id],
      client_secret: OAUTH_SETTINGS[:client_secret]
    }
  )

  if response.code != 200
    raise "Failed to get access token. HTTP Code: #{response.code}, Body: #{response.body}"
  end

  JSON.parse(response.body)
end