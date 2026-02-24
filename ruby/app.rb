# UserSpice OAuth Client - Ruby/Sinatra Example
#
# This is a Ruby/Sinatra implementation of an OAuth 2.0 client for UserSpice.
# It demonstrates the complete authorization code flow including:
# - CSRF protection via state parameter
# - Token exchange
# - UserInfo endpoint fetching
# - HMAC signature verification for response data
#
# Usage:
#   gem install sinatra sinatra-contrib httparty
#   ruby app.rb
#   Then visit http://localhost:4567/oauth_request in your browser

require 'sinatra'
require 'sinatra/reloader' if development?
require 'httparty'
require 'json'
require 'securerandom'
require 'base64'
require 'openssl'
require 'cgi'
require_relative 'oauth_config'

enable :sessions
set :session_secret, SecureRandom.hex(64)

# CSS styles for the HTML output
CSS_STYLES = <<~CSS
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
CSS

# Initiates the OAuth flow by redirecting to the authorization server
get '/oauth_request' do
  # Generate a random state for CSRF protection
  state = SecureRandom.hex(16)
  session[:oauth_state] = state

  # Build authorization URL
  auth_params = {
    response_type: 'code',
    client_id: OAUTH_SETTINGS[:client_id],
    redirect_uri: OAUTH_SETTINGS[:redirect_uri],
    state: state,
    scope: OAUTH_SETTINGS[:scope]
  }

  auth_url = "#{OAUTH_SETTINGS[:server_url]}users/auth/?#{URI.encode_www_form(auth_params)}"
  redirect auth_url
end

# Handles the OAuth callback after user authorization
get '/oauth_response' do
  # Check for OAuth errors
  if params[:error]
    error_desc = params[:error_description] || 'No description'
    return render_error("OAuth Error: #{params[:error]} - #{error_desc}")
  end

  # Verify required parameters
  unless params[:code] && params[:state]
    return render_error('Missing authorization code or state parameter')
  end

  # Verify state to prevent CSRF attacks
  if params[:state] != session[:oauth_state]
    return render_error('Invalid state parameter. Possible CSRF attack.')
  end

  # Clear state (one-time use)
  session.delete(:oauth_state)

  # Exchange code for access token
  begin
    token_data = exchange_code_for_token(params[:code])
  rescue StandardError => e
    return render_error("Token exchange failed: #{e.message}")
  end

  access_token = token_data['access_token']
  token_type = token_data['token_type'] || 'Bearer'
  expires_in = token_data['expires_in'] || 3600

  # Fetch user info from /userinfo endpoint
  user_info = nil
  user_info_error = nil
  begin
    user_info = fetch_user_info(access_token)
  rescue StandardError => e
    user_info_error = e.message
  end

  # Process response data (UserSpice specific)
  response_data = nil
  signature_status = 'none' # 'none', 'verified', 'unverified'

  if params[:response]
    begin
      decoded_response = Base64.decode64(params[:response])
    rescue StandardError => e
      return render_error("Failed to decode response data: #{e.message}")
    end

    # Verify HMAC signature if response_secret is configured
    response_secret = OAUTH_SETTINGS[:response_secret]
    if response_secret && !response_secret.empty?
      unless params[:signature]
        return render_error('Response signature missing but response_secret is configured. Possible tampering.')
      end

      expected_signature = OpenSSL::HMAC.hexdigest('SHA256', response_secret, decoded_response)

      # Timing-safe comparison
      unless secure_compare(expected_signature, params[:signature])
        return render_error('Invalid response signature. Possible tampering detected.')
      end

      signature_status = 'verified'
    elsif params[:signature]
      signature_status = 'unverified' # Signature provided but no secret to verify
    end

    begin
      response_data = JSON.parse(decoded_response)
    rescue JSON::ParserError => e
      return render_error("Failed to parse response data: #{e.message}")
    end
  end

  # Render success page
  render_success(access_token, token_type, expires_in, token_data, user_info, user_info_error, response_data, signature_status)
end

# Exchange the authorization code for an access token
def exchange_code_for_token(auth_code)
  token_url = "#{OAUTH_SETTINGS[:server_url]}users/auth/"

  response = HTTParty.post(token_url,
    body: {
      grant_type: 'authorization_code',
      code: auth_code,
      redirect_uri: OAUTH_SETTINGS[:redirect_uri],
      client_id: OAUTH_SETTINGS[:client_id],
      client_secret: OAUTH_SETTINGS[:client_secret]
    },
    timeout: 30
  )

  unless response.code == 200
    raise "HTTP #{response.code}: #{response.body}"
  end

  JSON.parse(response.body)
end

# Fetch user information from the OAuth server's userinfo endpoint
def fetch_user_info(access_token)
  user_info_url = "#{OAUTH_SETTINGS[:server_url]}users/auth/userinfo"

  response = HTTParty.get(user_info_url,
    headers: {
      'Authorization' => "Bearer #{access_token}",
      'Accept' => 'application/json'
    },
    timeout: 30
  )

  unless response.code == 200
    raise "HTTP #{response.code}: #{response.body}"
  end

  JSON.parse(response.body)
end

# Timing-safe string comparison to prevent timing attacks
def secure_compare(a, b)
  return false unless a.bytesize == b.bytesize

  l = a.unpack('C*')
  res = 0
  b.each_byte { |byte| res |= byte ^ l.shift }
  res == 0
end

# Render error page
def render_error(message)
  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OAuth Error</title>
        <style>#{CSS_STYLES}</style>
    </head>
    <body>
        <h1 class="error">OAuth Error</h1>
        <div class="error-box">#{CGI.escapeHTML(message)}</div>
        <p><a href="/oauth_request">Try again</a></p>
    </body>
    </html>
  HTML
end

# Render success page
def render_success(access_token, token_type, expires_in, token_data, user_info, user_info_error, response_data, signature_status)
  # User info section
  user_info_html = if user_info_error
    %(<div class="warning"><p>Could not fetch user info: #{CGI.escapeHTML(user_info_error)}</p></div>)
  else
    %(<pre>#{CGI.escapeHTML(JSON.pretty_generate(user_info))}</pre>)
  end

  # Response data section
  response_html = ''
  if response_data
    sig_html = case signature_status
    when 'verified'
      '<p class="signature-verified">HMAC Signature: Verified</p>'
    when 'unverified'
      <<~SIG
        <div class="warning">
            <p class="signature-warning">HMAC Signature: Not Verified (no response_secret configured)</p>
            <p>The server sent a signature but this client has no secret to verify it against.</p>
        </div>
      SIG
    else
      '<p class="signature-none">HMAC Signature: None (server did not sign response)</p>'
    end

    response_html = <<~RESP
      <h2>Response Data (UserSpice Specific)</h2>
      #{sig_html}
      <pre>#{CGI.escapeHTML(JSON.pretty_generate(response_data))}</pre>
    RESP

    # Add user data breakdown if present
    if response_data['userdata']
      response_html += '<h3>User Data</h3><ul>'
      response_data['userdata'].each do |key, value|
        display_value = value.is_a?(Hash) || value.is_a?(Array) ? JSON.generate(value) : value.to_s
        response_html += "<li><strong>#{CGI.escapeHTML(key)}:</strong> #{CGI.escapeHTML(display_value)}</li>"
      end
      response_html += '</ul>'
    end
  end

  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OAuth Authentication Successful</title>
        <style>#{CSS_STYLES}</style>
    </head>
    <body>
        <h1>Authentication Successful!</h1>

        <div class="info-box">
            <strong>Access Token:</strong>
            <div class="token">#{CGI.escapeHTML(access_token)}</div>
            <p><strong>Token Type:</strong> #{CGI.escapeHTML(token_type)}</p>
            <p><strong>Expires In:</strong> #{expires_in} seconds</p>
        </div>

        <h2>User Info from /userinfo Endpoint</h2>
        #{user_info_html}

        #{response_html}

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
        <pre>#{CGI.escapeHTML(JSON.pretty_generate(token_data))}</pre>
    </body>
    </html>
  HTML
end
