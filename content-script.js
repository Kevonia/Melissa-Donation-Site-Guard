
// @license MIT
// Jamaica Donation Guard - Browser Extension Security Script
// Detects potential donation scam websites targeting Jamaica hurricane relief

/**
 * @fileoverview Security detection script for identifying potential donation scam websites
 * targeting Jamaica hurricane relief efforts. Checks against known suspicious domains,
 * verifies official government domains, and analyzes page content for scam indicators.
 * @version 1.0.0
 * @author  Kevonia Tomlinson
 */
(async () => {
  try {
    const resp = await new Promise((res) => chrome.runtime.sendMessage({ type: 'getLists' }, res));
    const suspect = resp.suspectDomains || [];
    const trusted = resp.trustedDomains || [];
    const official = resp.officialPortal || 'supportjamaica.gov.jm';
    const hostname = window.location.hostname.toLowerCase();

    if (suspect.includes(hostname)) {
      showWarning('This domain has been identified as suspicious by JaCIRT. Do NOT enter payment or personal info. Use ' + official);
      return;
    }

    if (!hostname.endsWith('.gov.jm') && (hostname.includes('jamaica') || /melissa|hurricane|relief|donat/i.test(hostname))) {
      showWarning('This site looks like a donation collection page but does NOT end with .gov.jm. The official donation portal is ' + official + '. Be cautious.');
      return;
    }

    const forms = Array.from(document.querySelectorAll('form'));
    for (const f of forms) {
      const text = (f.innerText || '') + ' ' + (f.action || '');
      if (/donat|pay|contribute|give|fundrais/i.test(text)) {
        const action = (f.action || '').toLowerCase();
        if (action && !action.includes(hostname) && !action.includes('supportjamaica.gov.jm')) {
          showWarning('This donation form submits data to a third-party endpoint (' + action + '). Verify recipient before entering payment info.');
          return;
        }
      }
    }

    const bodyText = document.body.innerText || '';
    if (/urgent|immediately|act now|send money|paypal|western union|venmo|gift card/i.test(bodyText)) {
      if (!trusted.includes(hostname) && !hostname.endsWith('.gov.jm')) {
        showWarning('This page contains urgent-sounding donation requests. Scammers use urgency to trick donors. Confirm via official channels: ' + official);
        return;
      }
    }

    // --- Improved Domain Similarity Check ---
    function normalizedLevenshtein(a, b) {
      a = a.toLowerCase().replace(/[^a-z0-9]/g, '');
      b = b.toLowerCase().replace(/[^a-z0-9]/g, '');

      if (!a.length || !b.length) return 0;
      const dp = Array.from({ length: a.length + 1 }, (_, i) =>
        Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
      );

      for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
          const cost = a[i - 1] === b[j - 1] ? 0 : 1;
          dp[i][j] = Math.min(
            dp[i - 1][j] + 1,
            dp[i][j - 1] + 1,
            dp[i - 1][j - 1] + cost
          );
        }
      }

      const dist = dp[a.length][b.length];
      return 1 - dist / Math.max(a.length, b.length);
    }

    const sim = normalizedLevenshtein(hostname, official);
    if (sim > 0.85 && hostname !== official) {
      showWarning(`⚠️ This domain (${hostname}) looks very similar to the official portal (${official}). Verify the URL carefully.`);
      return;
    }

  } catch (e) {
    console.error('Detector error', e);
  }
   
  function showWarning(message) {
    if (document.getElementById('mdg-warning-overlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'mdg-warning-overlay';
    overlay.style.position = 'fixed';
    overlay.style.zIndex = '2147483647';
    overlay.style.left = '12px';
    overlay.style.bottom = '12px';
    overlay.style.maxWidth = '420px';
    overlay.style.padding = '14px';
    overlay.style.background = 'white';
    overlay.style.border = '3px solid #c62828';
    overlay.style.borderRadius = '10px';
    overlay.style.boxShadow = '0 6px 18px rgba(0,0,0,0.25)';
    overlay.style.fontFamily = 'Arial, sans-serif';
    overlay.style.color = '#111';

    overlay.innerHTML = `
      <strong style="color:#c62828;display:block;margin-bottom:6px">⚠️ Donation Site Warning</strong>
      <div style="font-size:13px;margin-bottom:8px">${escapeHtml(message)}</div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <a href="https://www.supportjamaica.gov.jm" target="_blank" rel="noopener" style="text-decoration:none;padding:6px 10px;border-radius:6px;border:1px solid #ccc">Go to official portal</a>
        <button id="mdg-dismiss" style="padding:6px 10px;border-radius:6px;border:1px solid #ccc;background:#eee">Dismiss</button>
      </div>
    `;

    document.body.appendChild(overlay);
    document.getElementById('mdg-dismiss').addEventListener('click', () => overlay.remove());

    function escapeHtml(s) {
      return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
  }
})();
