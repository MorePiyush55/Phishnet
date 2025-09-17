const express = require('express');
const router = express.Router();
const controller = require('../controllers/authController');

// Redirects to Google OAuth consent screen
router.get('/google', controller.initiateGoogleOAuth);

// Google OAuth callback
router.get('/google/callback', controller.handleGoogleCallback);

// Logout route
router.post('/logout', controller.logout);

module.exports = router;