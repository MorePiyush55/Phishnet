import { api } from './auth';

/**
 * Utility functions for making authenticated calls to Gmail API endpoints
 */

/**
 * Analyze user's Gmail emails for phishing threats
 * @param {number} maxEmails - Maximum number of emails to fetch (default: 10)
 * @returns {Promise<Object>} Email analysis results
 */
export async function analyzeGmailEmails(maxEmails = 10) {
  try {
    const response = await api.post('/api/gmail-simple/analyze', {
      max_emails: maxEmails
    });
    
    return response.data;
  } catch (error) {
    console.error('Error analyzing Gmail emails:', error);
    throw error;
  }
}

/**
 * Check if user has stored Gmail OAuth tokens
 * @param {string} userEmail - User's email address
 * @returns {Promise<Object>} Token status information
 */
export async function checkGmailTokens(userEmail) {
  try {
    const response = await api.get(`/api/gmail-simple/check-tokens/${encodeURIComponent(userEmail)}`);
    return response.data;
  } catch (error) {
    console.error('Error checking Gmail tokens:', error);
    throw error;
  }
}

/**
 * Get Gmail API health status
 * @returns {Promise<Object>} Health status
 */
export async function getGmailHealth() {
  try {
    const response = await api.get('/api/gmail-simple/health');
    return response.data;
  } catch (error) {
    console.error('Error getting Gmail health:', error);
    throw error;
  }
}