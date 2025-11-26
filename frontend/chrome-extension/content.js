// PhishNet Content Script
// Injects a button into Gmail to trigger on-demand analysis
// Also handles token extraction from backend callback

console.log("PhishNet extension loaded");

// --- Token Extraction Logic ---
if (window.location.href.includes("/api/v2/auth/callback")) {
    const tokenData = document.getElementById('phishnet-token-data');
    if (tokenData) {
        const token = tokenData.getAttribute('data-token');
        const user = tokenData.getAttribute('data-user');

        if (token) {
            chrome.runtime.sendMessage({
                action: "save_token",
                token: token,
                user_id: user
            }, () => {
                console.log("Token saved to background");
                // Optional: Close tab or redirect
                // window.close(); 
            });
        }
    }
}

// --- Gmail Button Injection Logic ---

function injectButton() {
    // Gmail's DOM is complex. We look for the toolbar.
    // Try multiple selectors for robustness
    const selectors = [
        '.iH',          // Top toolbar in single email view
        '.G-atb',       // Classic toolbar (often in inbox)
        '.adF',         // Action bar above email
        '.gA.gt',       // Reply/Forward area
        '.bJ'           // Another toolbar variation
    ];

    let toolbar = null;
    // Prioritize the toolbar that is actually visible and likely the single email one
    for (const sel of selectors) {
        const found = document.querySelectorAll(sel);
        for (const el of found) {
            if (el.offsetParent !== null) { // Check if visible
                toolbar = el;
                break;
            }
        }
        if (toolbar) break;
    }

    if (toolbar && !document.getElementById('phishnet-check-btn')) {
        const btn = document.createElement('div');
        btn.id = 'phishnet-check-btn';
        // Gmail button classes - might need updates if Gmail changes
        btn.className = 'T-I J-J5-Ji T-I-Js-IF ar7 T-I-ax7 L3';
        btn.innerHTML = '🔍 Check PhishNet';
        btn.style.marginLeft = '10px';
        btn.style.backgroundColor = '#d93025';
        btn.style.color = 'white';
        btn.style.fontWeight = 'bold';
        btn.style.cursor = 'pointer';
        btn.style.borderRadius = '4px';
        btn.style.padding = '0 8px';
        btn.style.display = 'inline-flex';
        btn.style.alignItems = 'center';
        btn.style.height = '24px';

        btn.onclick = async (e) => {
            e.stopPropagation(); // Prevent Gmail from handling the click

            // Get Message ID from URL (e.g., #inbox/FMfcgzGrc...)
            const hash = window.location.hash;
            let messageId = hash.split('/').pop();

            // Remove any query parameters or extra data
            if (messageId.includes('?')) {
                messageId = messageId.split('?')[0];
            }

            if (!messageId || messageId.length < 5 || messageId === 'inbox' || messageId === 'starred' || messageId === 'sent') {
                alert("Could not detect a valid Message ID. Please open a specific email.");
                return;
            }

            btn.innerHTML = '⏳ Checking...';

            // Set a timeout to reset button if backend hangs
            const timeoutId = setTimeout(() => {
                if (btn.innerHTML === '⏳ Checking...') {
                    btn.innerHTML = '🔍 Check PhishNet';
                    alert("Request timed out. Please try again.");
                }
            }, 15000); // 15 seconds timeout

            // Send message to background script
            try {
                chrome.runtime.sendMessage({
                    action: "analyze_email",
                    messageId: messageId
                }, (response) => {
                    clearTimeout(timeoutId);
                    btn.innerHTML = '🔍 Check PhishNet';

                    if (chrome.runtime.lastError) {
                        alert("Extension Error: " + chrome.runtime.lastError.message);
                        return;
                    }

                    if (response && response.success) {
                        const score = response.data.threat_score;
                        const risk = response.data.risk_level;
                        alert(`Analysis Complete!\n\nRisk Level: ${risk}\nThreat Score: ${score}/100`);
                    } else {
                        const errorMsg = response ? response.error : "Unknown error";
                        alert("Analysis failed: " + errorMsg);
                    }
                });
            } catch (err) {
                clearTimeout(timeoutId);
                btn.innerHTML = '🔍 Check PhishNet';
                alert("Failed to send request: " + err.message);
            }
        };

        // Append to the end of the toolbar
        toolbar.appendChild(btn);
    }
}

// Observe DOM changes to inject button when email is opened
// Use a debounce to avoid performance hit
let timeout = null;
const observer = new MutationObserver(() => {
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(injectButton, 500);
});

if (!window.location.href.includes("/api/v2/auth/callback")) {
    observer.observe(document.body, { childList: true, subtree: true });
}
