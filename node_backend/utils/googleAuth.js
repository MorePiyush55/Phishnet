const { google } = require('googleapis');

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
  // do not throw; allow library to be loaded in non-Node environments for static analysis
  console.warn('Google OAuth: missing CLIENT_ID/CLIENT_SECRET/REDIRECT_URI in environment');
}

const oauth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
);

const SCOPES = [
  'openid',
  'profile',
  'email',
  'https://www.googleapis.com/auth/gmail.readonly'
];

function getAuthUrl() {
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
    prompt: 'consent'
  });
}

async function getTokenFromCode(code) {
  const { tokens } = await oauth2Client.getToken(code);
  oauth2Client.setCredentials(tokens);
  return { oauth2Client, tokens };
}

async function refreshAccessToken(refreshToken) {
  const client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
  client.setCredentials({ refresh_token: refreshToken });
  const res = await client.refreshAccessToken();
  return res.credentials; // contains access_token, expiry_date, etc.
}

async function getUserInfo(client) {
  const oauth2 = google.oauth2({ version: 'v2', auth: client });
  return await oauth2.userinfo.get();
}

module.exports = {
  getAuthUrl,
  getTokenFromCode,
  refreshAccessToken,
  getUserInfo
};