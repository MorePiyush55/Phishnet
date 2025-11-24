// PhishNet Background Script

const API_BASE = "http://localhost:8000/api/v2";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze_email") {
        analyzeEmail(request.messageId).then(sendResponse);
        return true; // Keep channel open for async response
    }
});

async function analyzeEmail(messageId) {
    try {
        // 1. Get User ID (mock for now, should come from storage/auth)
        const userId = "user_123";

        // 2. Call Backend
        const response = await fetch(`${API_BASE}/request-check`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message_id: messageId,
                user_id: userId,
                store_consent: false
            })
        });

        const data = await response.json();

        if (data.need_oauth) {
            // Open OAuth tab
            chrome.tabs.create({ url: data.oauth_url });
            return { success: false, error: "Authentication required. Please log in via the new tab." };
        }

        return { success: true, data: data.analysis };

    } catch (error) {
        return { success: false, error: error.message };
    }
}
