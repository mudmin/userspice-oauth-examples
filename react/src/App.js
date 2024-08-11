import React from 'react';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import OAuthRequest from './OAuthRequest';
import OAuthResponse from './OAuthResponse';

function App() {
  return (
    <Router>
      <div className="App">
        <nav>
          <ul>
            <li>
              <Link to="/oauth_request">Start OAuth Flow</Link>
            </li>
          </ul>
        </nav>

        <Routes>
          <Route path="/oauth_request" element={<OAuthRequest />} />
          <Route path="/oauth_response" element={<OAuthResponse />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;