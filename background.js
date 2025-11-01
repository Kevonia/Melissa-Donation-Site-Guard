const OFFICIAL_PORTAL = 'supportjamaica.gov.jm';

const SUSPECT_DOMAINS = [
  'jamaicahurricanehelp.net',
  'jamaicahurricanehelp.org',
  'jamaica-hurricane-help.com',
  'melissareliefjamaica.net',
  'melissareliefjamaica.com',
  'melissareliefjamaica.org',
  'supportjamaicagovjm.com',
  'supportjamaicagovjm.net'
];

const TRUSTED_DOMAINS = [
  OFFICIAL_PORTAL,
  'jacirt.gov.jm',
  'opm.gov.jm'
];

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({suspectDomains: SUSPECT_DOMAINS, trustedDomains: TRUSTED_DOMAINS, officialPortal: OFFICIAL_PORTAL});
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'getLists') {
    chrome.storage.local.get(['suspectDomains','trustedDomains','officialPortal'], (items) => {
      sendResponse(items);
    });
    return true;
  }
});


