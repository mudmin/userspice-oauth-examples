import React, { useState, useEffect } from 'react';
import axios from 'axios';

const OAUTH_SETTINGS = {
  server_url: 'https://your_server.com/',
  client_id: 'your_client_id',
  client_secret: 'your_client_secret',
  redirect_uri: 'http://localhost:3000/oauth_response',
};

function OAuthResponse() {
  const [tokenData, setTokenData] = useState(null);
  const [responseData, setResponseData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const response = urlParams.get('response');

    if (state !== localStorage.getItem('oauth_state')) {
      setError('Invalid state parameter');
      return;
    }

    // Decode and parse the response data
    if (response) {
      try {
        const decodedResponse = JSON.parse(atob(response));
        setResponseData(decodedResponse);
      } catch (decodeError) {
        console.error('Error decoding response:', decodeError);
        setError('Error decoding response');
      }
    }

    // We don't need to exchange the code for a token in this case
    // as the server has already provided the user data in the response
    setTokenData({ access_token: code });

  }, []);

  if (error) {
    return <div>Error: {error}</div>;
  }

  if (!responseData) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h1>Authentication successful!</h1>
      <p>Access Token (Code): {tokenData?.access_token}</p>
      
      <h2>User Data:</h2>
      <pre>{JSON.stringify(responseData.userdata, null, 2)}</pre>

      <h2>Tags:</h2>
      <pre>{JSON.stringify(responseData.tags, null, 2)}</pre>

      <h2>Instructions:</h2>
      <pre>{JSON.stringify(responseData.instructions, null, 2)}</pre>

      <p>Your login function here. You can now use the access token to make authenticated requests.</p>
    </div>
  );
}

export default OAuthResponse;