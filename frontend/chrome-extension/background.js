// PhishNet Background Script

// const API_BASE = "http://localhost:8002/api/v2";
const API_BASE = "https://phishnet-backend-iuoc.onrender.com/api/v2";

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze_email") {
        analyzeEmail(request.messageId).then(sendResponse);
        return true; // Keep channel open for async response
    }

    if (request.action === "save_token") {
        chrome.storage.local.set({
            phishnet_token: request.token,
            phishnet_user: request.user_id
        }, () => {
            console.log("Token stored successfully");
            sendResponse({ success: true });
        });
        return true;
    }
});

async function analyzeEmail(messageId) {
    try {
        // 1. Get stored token and user ID
        const storage = await chrome.storage.local.get(['phishnet_token', 'phishnet_user']);
        const token = storage.phishnet_token;
        const userId = storage.phishnet_user || "anonymous_user";

        console.log("Analyzing email:", messageId, "User:", userId, "Has Token:", !!token);

        // 2. Call Backend
        const response = await fetch(`${API_BASE}/request-check`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message_id: messageId,
                user_id: userId,
                access_token: token || null, // Send token if we have it
                store_consent: false
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error("Backend error:", response.status, errorText);
            return { success: false, error: `Server error (${response.status}): ${errorText}` };
        }

        const data = await response.json();

        if (data.need_oauth) {
            // Open OAuth tab
            chrome.tabs.create({ url: data.oauth_url });
            return { success: false, error: "Authentication required. A new tab has been opened for login." };
        }

        if (!data.success) {
            return { success: false, error: data.message || "Unknown backend error" };
        }

        return { success: true, data: data.analysis };

    } catch (error) {
        console.error("Analysis failed:", error);
        return { success: false, error: "Network/Extension Error: " + error.message };
    }
}
