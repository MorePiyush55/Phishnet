const jwt = require('jsonwebtoken');
const googleAuth = require('../utils/googleAuth');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

exports.initiateGoogleOAuth = async (req, res) => {
  try {
    const url = googleAuth.getAuthUrl();
    return res.redirect(url);
  } catch (err) {
    console.error('Error initiating OAuth', err);
    return res.status(500).json({ error: 'Failed to initiate OAuth' });
  }
};

exports.handleGoogleCallback = async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state;
    if (!code) return res.status(400).json({ error: 'Missing code' });

    const tokenResponse = await googleAuth.getTokenFromCode(code);
    const oauth2Client = tokenResponse.oauth2Client;
    const tokens = tokenResponse.tokens;

    const userInfo = await googleAuth.getUserInfo(oauth2Client);

    // Create JWT for session
    const payload = {
      sub: userInfo.data.id,
      email: userInfo.data.email,
      name: userInfo.data.name
    };

    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    // For demo we return tokens and basic user info
    // In production: create user in DB, set secure httpOnly cookie, etc.
    return res.json({
      accessToken,
      refreshToken: tokens.refresh_token || null,
      expires_in: tokens.expires_in,
      user: userInfo.data
    });
  } catch (err) {
    console.error('OAuth callback error', err);
    return res.status(500).json({ error: 'OAuth callback failed' });
  }
};

exports.logout = (req, res) => {
  // Clear session or cookies as appropriate
  req.session = null;
  res.json({ success: true, message: 'Logged out' });
};