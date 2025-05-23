// This is a secure React app that loads encrypted password data from a Google Spreadsheet,
// uses Google OAuth to authenticate only the owner's account, and displays obscured passwords
// derived using custom logic.

import React, { useState, useEffect } from 'react';
import { GoogleOAuthProvider, GoogleLogin } from '@react-oauth/google';
import jwt_decode from 'jwt-decode';
import CryptoJS from 'crypto-js';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SHEET_ID = process.env.GOOGLE_SHEET_ID;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const OWNER_EMAIL = process.env.OWNER_EMAIL;

function App() {
  const [userEmail, setUserEmail] = useState(null);
  const [accessToken, setAccessToken] = useState(null);
  const [apps, setApps] = useState([]);
  const [showPasswords, setShowPasswords] = useState({});
  const [isLoading, setIsLoading] = useState(false);

  const handleLoginSuccess = async credentialResponse => {
    const decoded = jwt_decode(credentialResponse.credential);
    if (decoded.email === OWNER_EMAIL) {
      setUserEmail(decoded.email);

      // Exchange the ID token for an access token using Google's OAuth2 token endpoint
      const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: credentialResponse.code,
          client_id: GOOGLE_CLIENT_ID,
          redirect_uri: window.location.origin,
          code_verifier: '<OPTIONAL_VERIFIER_IF_PKCE>' // if you're using PKCE
        })
      });
      const tokenData = await res.json();
      setAccessToken(tokenData.access_token);
    } else {
      alert("Access denied: Not authorized");
    }
  };

  useEffect(() => {
    if (userEmail && accessToken) {
      setIsLoading(true);

      const fetchData = async () => {
        const range = 'Sheet1!A2:B'; // Adjust range as needed
        const res = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${GOOGLE_SHEET_ID}/values/${range}`, {
          headers: {
            Authorization: `Bearer ${accessToken}`
          }
        });

        const data = await res.json();
        const parsedApps = (data.values || []).map(([app, encrypted]) => {
          try {
            const bytes = CryptoJS.AES.decrypt(encrypted, ENCRYPTION_KEY);
            const decrypted = bytes.toString(CryptoJS.enc.Utf8);
            return { app, secret: decrypted };
          } catch (e) {
            return { app, secret: '' };
          }
        });
        setApps(parsedApps);
        setIsLoading(false);
      };

      fetchData();
    }
  }, [userEmail, accessToken]);

  const getDerivedPassword = (rawSecret) => {
    // Replace with your custom logic. Obfuscate with Webpack Obfuscator if desired.
    return `***${rawSecret.slice(0, 3)}***`;
  };

  if (!userEmail) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen gap-4">
        <h2 className="text-2xl font-bold">Login</h2>
        <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
          <GoogleLogin
            onSuccess={handleLoginSuccess}
            onError={() => alert('Login Failed')}
            useOneTap
          />
        </GoogleOAuthProvider>
      </div>
    );
  }

  return (
    <div className="p-4 max-w-2xl mx-auto">
      <h2 className="text-2xl font-bold mb-4">Welcome, {userEmail}</h2>
      {isLoading && <p>Loading apps...</p>}
      {apps.map((app, index) => (
        <Card key={index} className="mb-2">
          <CardContent className="flex justify-between items-center p-4">
            <span>{app.app}</span>
            <span className="flex gap-2 items-center">
              <code className="font-mono">
                {showPasswords[index] ? getDerivedPassword(app.secret) : "********"}
              </code>
              <Button onClick={() =>
                setShowPasswords(prev => ({
                  ...prev,
                  [index]: !prev[index]
                }))
              }>
                {showPasswords[index] ? "Hide" : "Show"}
              </Button>
            </span>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

export default App;
