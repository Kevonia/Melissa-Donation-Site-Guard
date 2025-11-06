// Background service worker for Jamaica Donation Guard
const DEFAULT_SUSPECT_DOMAINS = [
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

const DEFAULT_TRUSTED_DOMAINS = [
  'opm.gov.jm',
  'supportjamaica.gov.jm',
  'mof.gov.jm',
  'jamcovid19.moh.gov.jm',
  'jis.gov.jm',
  'psoj.org',
  'jcdt.org.jm'
];

const DEFAULT_OFFICIAL_PORTAL = 'supportjamaica.gov.jm';

// Configuration
const GITHUB_RAW_URL = 'https://raw.githubusercontent.com/your-username/your-repo/main/domain-lists.json';
const UPDATE_INTERVAL_MS = 3 * 60 * 60 * 1000; // 3 hours

// Initialize the service worker
chrome.runtime.onInstalled.addListener(() => {
  console.log('Jamaica Donation Guard installed/updated');
  initializeDomainLists();
  setupPeriodicUpdates();
});

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'getLists':
      chrome.storage.local.get(['suspectDomains', 'trustedDomains', 'officialPortal', 'lastUpdated'], (result) => {
        sendResponse({
          suspectDomains: result.suspectDomains || DEFAULT_SUSPECT_DOMAINS,
          trustedDomains: result.trustedDomains || DEFAULT_TRUSTED_DOMAINS,
          officialPortal: result.officialPortal || DEFAULT_OFFICIAL_PORTAL,
          lastUpdated: result.lastUpdated || Date.now()
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

    case 'forceUpdate':
      fetchDomainListsFromGitHub().then(success => {
        sendResponse({ success });
      });
      return true;

    case 'getLastUpdate':
      chrome.storage.local.get(['lastUpdated', 'lastUpdateError'], (result) => {
        sendResponse({
          lastUpdated: result.lastUpdated,
          lastUpdateError: result.lastUpdateError
        });
      });
      return true;
  }
});

// Initialize domain lists on installation
async function initializeDomainLists() {
  const result = await chrome.storage.local.get(['suspectDomains', 'lastUpdated']);
  
  // If no domains are stored or it's been more than 3 hours, fetch from GitHub
  if (!result.suspectDomains || !result.lastUpdated || (Date.now() - result.lastUpdated) > UPDATE_INTERVAL_MS) {
    await fetchDomainListsFromGitHub();
  }
}

// Set up periodic updates
function setupPeriodicUpdates() {
  // Update immediately on startup
  fetchDomainListsFromGitHub();

  // Set up periodic updates every 3 hours
  setInterval(() => {
    fetchDomainListsFromGitHub();
  }, UPDATE_INTERVAL_MS);
}

// Fetch domain lists from GitHub
async function fetchDomainListsFromGitHub() {
  try {
    console.log('Fetching domain lists from GitHub...');
    
    const response = await fetch(GITHUB_RAW_URL, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache'
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const domainData = await response.json();
    
    // Validate the response structure
    if (!domainData.suspectDomains || !domainData.trustedDomains || !domainData.officialPortal) {
      throw new Error('Invalid domain list format from GitHub');
    }

    // Save to local storage
    await chrome.storage.local.set({
      suspectDomains: domainData.suspectDomains,
      trustedDomains: domainData.trustedDomains,
      officialPortal: domainData.officialPortal,
      lastUpdated: Date.now(),
      lastUpdateError: null
    });

    console.log('Domain lists updated successfully from GitHub');
    
    // Notify all content scripts about the update
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (tab.url && tab.url.startsWith('http')) {
          chrome.tabs.sendMessage(tab.id, {
            type: 'listsUpdated',
            timestamp: Date.now()
          }).catch(() => {
            // Ignore errors for tabs that don't have content scripts
          });
        }
      });
    });

    return true;
  } catch (error) {
    console.error('Failed to fetch domain lists from GitHub:', error);
    
    // Save error information
    await chrome.storage.local.set({
      lastUpdateError: {
        message: error.message,
        timestamp: Date.now()
      }
    });

    return false;
  }
}

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

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  console.log('Jamaica Donation Guard starting up');
  initializeDomainLists();
});