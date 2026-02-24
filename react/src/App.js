import React from 'react';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import OAuthRequest from './OAuthRequest';
import OAuthResponse from './OAuthResponse';
import './App.css';

function Home() {
  return (
    <div className="oauth-container">
      <div className="oauth-card">
        <h1>UserSpice OAuth Demo</h1>
        <p className="subtitle">React Client Example</p>

        <div className="warning-box">
          <strong>Security Notice:</strong> This is a frontend-only demo.
          In production, token exchange and HMAC verification should happen
          on a backend server. Never expose client secrets in frontend code.
        </div>

        <Link to="/oauth_request" className="oauth-button">
          Login with UserSpice OAuth
        </Link>

        <div className="info-section">
          <h3>OAuth Flow</h3>
          <ol>
            <li>Click the login button above</li>
            <li>You'll be redirected to the UserSpice OAuth server</li>
            <li>Login and authorize the application</li>
            <li>You'll be redirected back with your user data</li>
          </ol>
        </div>
      </div>
    </div>
  );
}

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/oauth_request" element={<OAuthRequest />} />
          <Route path="/oauth_response" element={<OAuthResponse />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
