(async () => {
  const statusEl = document.getElementById('status');
  const [tab] = await chrome.tabs.query({active:true,lastFocusedWindow:true});
  const hostname = tab?.url ? new URL(tab.url).hostname : '';

  chrome.runtime.sendMessage({type: 'getLists'}, (resp) => {
    const suspect = resp.suspectDomains || [];
    const trusted = resp.trustedDomains || [];
    const official = resp.officialPortal || 'supportjamaica.gov.jm';

    if (!hostname) {
      statusEl.innerText = 'No active tab detected.';
      return;
    }

    if (suspect.includes(hostname)) {
      statusEl.innerHTML = `<div class="danger">This domain is listed as suspicious.</div><small>Do not enter payment details.</small>`;
    } else if (!hostname.endsWith('.gov.jm') && /jamaica|melissa|hurricane|relief|donat/i.test(hostname)) {
      statusEl.innerHTML = `<div class="danger">Looks donation-related but is NOT a .gov.jm domain.</div><small>Official portal: ${official}</small>`;
    } else if (trusted.includes(hostname) || hostname.endsWith('.gov.jm')) {
      statusEl.innerHTML = `<div class="ok">This domain appears trusted.</div><small>Always verify before donating.</small>`;
    } else {
      statusEl.innerHTML = `<div>Unknown — use caution. Official portal: ${official}</div>`;
    }
  });

  document.getElementById('open-official').addEventListener('click', () => {
    chrome.tabs.create({url: 'https://www.supportjamaica.gov.jm'});
  });
  document.getElementById('report-site').addEventListener('click', async () => {
    const reportEmail = 'jacirt@gov.jm';
    if (confirm('Open email client to report this site to JaCIRT?')) {
      const subject = encodeURIComponent('Suspicious donation site report');
      const body = encodeURIComponent(`I found a suspicious donation site: ${hostname}`);
      window.open(`mailto:${reportEmail}?subject=${subject}&body=${body}`);
    }
  });
})();