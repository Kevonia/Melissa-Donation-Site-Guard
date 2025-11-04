// Background service worker for Jamaica Donation Guard
const SUSPECT_DOMAINS = [
  'jamaicahurricanehelp.net',
  'jamaicahurricanehelp.org',
  'jamaica-hurricane-help.com',
  'melissareliefjamaica.net',
  'melissareliefjamaica.com',
  'melissareliefjamaica.org',
  'supportjamaicagovjm.com',
  'supportjamaicagovjm.net',
  'supportjamaica.gov.jm',
  'hurricanemelissareliefconcert.com',
  'aidjamaica.com',
  'melissarelief.net',
  'jamaicahelps.org',
  'jamaica-relief.com',
  'jamaicaaid.com',
  'helpjamaicatoday.org',
  'helpmelissa.com',
  'donatetojamaica.org',
  'helpjamaicatoday.com',
  'jamaicareliefministries.org',
  'melissahelp.org',
  'melissafund.org',
  'melissadonation.org',
  'onelovereliefjamaica.org',
  'onelovereliefjamaica.com',
  'hurricanemelissajamaica.org'
];

const TRUSTED_DOMAINS = [
  'opm.gov.jm',
  'supportjamaica.gov.jm',
  'mof.gov.jm',
  'jamcovid19.moh.gov.jm',
  'jis.gov.jm',
  'psoj.org',
  'jcdt.org.jm'
];

const OFFICIAL_PORTAL = 'supportjamaica.gov.jm';


// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'getLists':
      chrome.storage.local.get(['suspectDomains', 'trustedDomains', 'officialPortal'], (result) => {
        sendResponse({
          suspectDomains: result.suspectDomains || SUSPECT_DOMAINS,
          trustedDomains: result.trustedDomains || TRUSTED_DOMAINS,
          officialPortal: OFFICIAL_PORTAL
        });
      });
      return true;

    case 'reportSite':
      reportSuspiciousSite(request.url, request.hostname);
      sendResponse({ success: true });
      break;

    case 'logDetection':
      logDetectionEvent(request.details);
      break;
  }
});

async function reportSuspiciousSite(url, hostname) {
  // Log the report locally
  const report = {
    url,
    hostname,
    timestamp: Date.now(),
    userAgent: navigator.userAgent
  };
  
  const { reports = [] } = await chrome.storage.local.get('reports');
  reports.push(report);
  await chrome.storage.local.set({ reports });
  
  // In a real implementation, this would send to a backend service
  console.log('Suspicious site reported:', report);
}

async function logDetectionEvent(details) {
  const { detections = [] } = await chrome.storage.local.get('detections');
  detections.push({
    ...details,
    timestamp: Date.now()
  });
  await chrome.storage.local.set({ detections });
}