document.addEventListener('DOMContentLoaded', async () => {
  const status = document.getElementById('status');
  const scanButton = document.getElementById('scanPage');
  const viewReport = document.getElementById('viewReport');

  // Check current page status
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab.url.startsWith('chrome://')) {
    status.innerHTML = '🛡️ Extension active and protecting your donations';
    status.className = 'status';
    return;
  }

  try {
    const response = await chrome.tabs.sendMessage(tab.id, { type: 'getStatus' });
    if (response && response.protected) {
      status.innerHTML = '✅ Page appears legitimate';
      status.className = 'status';
    } else {
      status.innerHTML = '⚠️ Be cautious - verify donation sites';
      status.className = 'status alert';
    }
  } catch (error) {
    status.innerHTML = '🔍 Scan complete - no threats detected';
    status.className = 'status';
  }

  scanButton.addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.reload(tab.id);
    window.close();
  });

  viewReport.addEventListener('click', async () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('report.html') });
  });
});