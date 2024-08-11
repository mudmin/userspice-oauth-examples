import React, { useEffect } from 'react';

const OAUTH_SETTINGS = {
  server_url: 'https://your_server.com/',
  client_id: 'your_client_id',
  redirect_uri: 'http://localhost:3000/oauth_response',
};

function OAuthRequest() {
  useEffect(() => {
    const state = Math.random().toString(36).substring(7);
    localStorage.setItem('oauth_state', state);

    const authParams = new URLSearchParams({
      response_type: 'code',
      client_id: OAUTH_SETTINGS.client_id,
      redirect_uri: OAUTH_SETTINGS.redirect_uri,
      state: state,
      scope: 'profile'
    });

    const authUrl = `${OAUTH_SETTINGS.server_url}usersc/plugins/oauth_server/auth.php?${authParams}`;
    window.location.href = authUrl;
  }, []);

  return <div>Redirecting to OAuth server...</div>;
}

export default OAuthRequest;