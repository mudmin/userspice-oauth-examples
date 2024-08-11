const express = require('express');
const session = require('express-session');
const axios = require('axios');
const crypto = require('crypto');
const querystring = require('querystring');

const app = express();
const port = 3000;

const OAUTH_SETTINGS = {
  server_url: 'https://your-server.com/',
  client_id: 'your_client_id',
  redirect_uri: 'http://localhost:3000/oauth_response'
};

app.use(express.json());
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true
}));

app.get('/oauth_request', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauth_state = state;

  const authParams = querystring.stringify({
    response_type: 'code',
    client_id: OAUTH_SETTINGS.client_id,
    redirect_uri: OAUTH_SETTINGS.redirect_uri,
    state: state,
    scope: 'profile'
  });

  res.redirect(`${OAUTH_SETTINGS.server_url}usersc/plugins/oauth_server/auth.php?${authParams}`);
});

app.get('/oauth_response', async (req, res) => {
  const { code, state, response } = req.query;

  if (state !== req.session.oauth_state) {
    return res.status(400).send('Invalid state parameter');
  }

  try {
    const tokenUrl = `${OAUTH_SETTINGS.server_url}usersc/plugins/oauth_server/auth.php`;
    const tokenData = await exchangeCodeForToken(tokenUrl, code);

    let responseHtml = `<h1>Authentication successful!</h1>`;
    responseHtml += `<p>Access Token: ${tokenData.access_token}</p>`;
    responseHtml += `<p>Expires In: ${tokenData.expires_in} seconds</p>`;

    responseHtml += '<h2>Detailed token data:</h2>';
    responseHtml += `<pre>${JSON.stringify(tokenData, null, 2)}</pre>`;

    if (response) {
      const decodedResponse = JSON.parse(Buffer.from(response, 'base64').toString());
      responseHtml += '<h2>Detailed response data:</h2>';
      responseHtml += `<pre>${JSON.stringify(decodedResponse, null, 2)}</pre>`;
    }

    responseHtml += '<p>Your login function here. You can now use the access token to make authenticated requests.</p>';

    res.send(responseHtml);
  } catch (error) {
    res.status(400).send(`Error: ${error.message}`);
  }
});

async function exchangeCodeForToken(tokenUrl, authCode) {
  const data = {
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: OAUTH_SETTINGS.redirect_uri,
    client_id: OAUTH_SETTINGS.client_id,
    client_secret: OAUTH_SETTINGS.client_secret
  };

  const response = await axios.post(tokenUrl, querystring.stringify(data), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  if (response.status !== 200) {
    throw new Error(`Failed to get access token. HTTP Code: ${response.status}`);
  }

  return response.data;
}

app.listen(port, () => {
  console.log(`OAuth app listening at http://localhost:${port}`);
});