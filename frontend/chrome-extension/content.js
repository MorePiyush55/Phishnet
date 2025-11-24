// PhishNet Content Script
// Injects a button into Gmail to trigger on-demand analysis

console.log("PhishNet extension loaded");

function injectButton() {
    // Gmail's DOM is complex and obfuscated. We look for the toolbar.
    // This selector targets the top toolbar in an open email.
    // Note: Selectors may need adjustment as Gmail updates.
    const toolbar = document.querySelector('.G-atb');

    if (toolbar && !document.getElementById('phishnet-check-btn')) {
        const btn = document.createElement('div');
        btn.id = 'phishnet-check-btn';
        btn.className = 'T-I J-J5-Ji T-I-Js-IF ar7 T-I-ax7 L3'; // Gmail button classes
        btn.innerHTML = '🔍 Check PhishNet';
        btn.style.marginLeft = '10px';
        btn.style.backgroundColor = '#d93025';
        btn.style.color = 'white';
        btn.style.fontWeight = 'bold';

        btn.onclick = async () => {
            // Get Message ID from URL (e.g., #inbox/FMfcgzGrc...)
            const hash = window.location.hash;
            const messageId = hash.split('/').pop();

            if (!messageId) {
                alert("Could not detect Message ID. Please open an email.");
                return;
            }

            // Send message to background script
            chrome.runtime.sendMessage({
                action: "analyze_email",
                messageId: messageId
            }, (response) => {
                if (response.success) {
                    alert(`Analysis Complete!\nScore: ${response.data.threat_score}\nRisk: ${response.data.risk_level}`);
                } else {
                    alert("Analysis failed: " + response.error);
                }
            });
        };

        toolbar.appendChild(btn);
    }
}

// Observe DOM changes to inject button when email is opened
const observer = new MutationObserver(injectButton);
observer.observe(document.body, { childList: true, subtree: true });
