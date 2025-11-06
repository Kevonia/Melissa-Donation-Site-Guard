// Enhanced content script for detecting fraudulent donation sites with domain reputation
class DonationGuardDetector {
  constructor() {
    this.config = {
      officialPortal: 'supportjamaica.gov.jm',
      similarityThreshold: 0.82,
      scanInterval: 5000,
      maxWarnings: 1,
      reputationCheckTimeout: 10000,
      minDomainAgeDays: 30
    };
    this.warningShown = false;
    this.detectionResults = {
      suspectDomain: false,
      similarDomain: false,
      unofficialDonation: false,
      suspiciousForm: false,
      scamContent: false,
      poorReputation: false,
      newDomain: false,
      suspiciousHosting: false
    };
    this.suspectDomains = [];
    this.trustedDomains = [];
    this.domainReputationCache = new Map();
  }

  async initialize() {
    try {
      await this.getDomainLists();
      await this.performComprehensiveSecurityScan();
      this.startContinuousMonitoring();
      
      // Also monitor for new forms added dynamically
      this.observeDOMChanges();
      
    } catch (error) {
  
      
    }
  }

  async getDomainLists() {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type: 'getLists' }, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
          return;
        }
        this.suspectDomains = response.suspectDomains || [];
        this.trustedDomains = response.trustedDomains || [];
        resolve(response);
      });
    });
  }

  observeDOMChanges() {
    const observer = new MutationObserver((mutations) => {
      let shouldRescan = false;
      
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.tagName === 'FORM' || node.querySelector('form')) {
                shouldRescan = true;
                break;
              }
            }
          }
        }
        if (shouldRescan) break;
      }
      
      if (shouldRescan && !this.warningShown) {
        this.scanForSuspiciousForms();
        // this.scanForScamContent();
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  async performComprehensiveSecurityScan() {
    const hostname = window.location.hostname.toLowerCase();
    
    // Check 1: Known suspect domains
    if (this.checkSuspectDomains(hostname)) return;
    
    // Check 2: Domain similarity
    if (this.checkDomainSimilarity(hostname)) return;
    
    // Check 3: Unofficial donation sites
    if (this.checkUnofficialDonationSite(hostname)) return;
    
    // Check 4: Domain reputation analysis
    await this.checkDomainReputation(hostname);
    
    // Check 5: Suspicious forms
    this.scanForSuspiciousForms();
    
    // Check 6: Scam content patterns
    // this.scanForScamContent();
  }

  checkSuspectDomains(hostname) {
    if (this.suspectDomains.includes(hostname)) {
      this.triggerWarning(
        `🚨 HIGH RISK: This domain (${hostname}) is on JaCIRT's suspicious list. ` +
        `Do NOT enter any personal or payment information. ` +
        `Official donations: ${this.config.officialPortal}`,
        'high'
      );
      this.detectionResults.suspectDomain = true;
      return true;
    }
    return false;
  }

  checkDomainSimilarity(hostname) {
    if (hostname === this.config.officialPortal) return false;
    
    const similarity = this.calculateSimilarity(hostname, this.config.officialPortal);
    if (similarity > this.config.similarityThreshold) {
      this.triggerWarning(
        `⚠️ SUSPICIOUS: This domain looks very similar to the official portal. ` +
        `Scammers often use similar names to trick donors. ` +
        `Real: ${this.config.officialPortal} | Current: ${hostname}`,
        'medium'
      );
      this.detectionResults.similarDomain = true;
      return true;
    }
    return false;
  }

  checkUnofficialDonationSite(hostname) {
    const isOfficial = hostname.endsWith('.gov.jm') || 
                      this.trustedDomains.includes(hostname);
    
    if (isOfficial) return false;

    // Check for Jamaica/hurricane references in domain
    const hasJamaicaReference = /jamaica|jam|hurricane|melissa|relief|aid|help|donat/i.test(hostname);
    
    // Check for donation content on page
    const hasDonationContent = this.hasDonationContent();
    
    if (hasJamaicaReference && hasDonationContent) {
      this.triggerWarning(
        `🔍 CAUTION: This appears to be a donation site but is NOT an official .gov.jm domain. ` +
        `Only ${this.config.officialPortal} is authorized for government relief donations.`,
        'medium'
      );
      this.detectionResults.unofficialDonation = true;
      return true;
    }
    return false;
  }

  async checkDomainReputation(hostname) {
    // Skip reputation check for trusted domains
    if (this.isTrustedDomain()) return;

    // Check cache first
    if (this.domainReputationCache.has(hostname)) {
      const reputation = this.domainReputationCache.get(hostname);
      this.evaluateReputationResults(reputation, hostname);
      return;
    }

    try {
      const reputation = await this.analyzeDomainReputation(hostname);
      this.domainReputationCache.set(hostname, reputation);
      this.evaluateReputationResults(reputation, hostname);
    } catch (error) {
      console.warn('Domain reputation analysis failed:', error);
    }
  }

  async analyzeDomainReputation(hostname) {
    const analysis = {
      domainAge: null,
      registrar: null,
      hostingProvider: null,
      blacklistStatus: [],
      sslValid: true,
      riskScore: 0,
      warnings: []
    };

    // 1. Domain age analysis
    analysis.domainAge = await this.checkDomainAge(hostname);
    if (analysis.domainAge && analysis.domainAge < this.config.minDomainAgeDays) {
      analysis.riskScore += 30;
      analysis.warnings.push(`New domain (${analysis.domainAge} days old)`);
      this.detectionResults.newDomain = true;
    }

    // 2. SSL certificate check
    analysis.sslValid = await this.checkSSLValidity(hostname);
    if (!analysis.sslValid) {
      analysis.riskScore += 20;
      analysis.warnings.push('Invalid or expired SSL certificate');
    }

    // 3. Blacklist check
    analysis.blacklistStatus = await this.checkBlacklists(hostname);
    if (analysis.blacklistStatus.length > 0) {
      analysis.riskScore += 40;
      analysis.warnings.push(`Listed on ${analysis.blacklistStatus.length} blacklist(s)`);
    }

    // 4. Hosting provider analysis
    analysis.hostingProvider = await this.analyzeHostingProvider(hostname);
    if (this.isSuspiciousHosting(analysis.hostingProvider)) {
      analysis.riskScore += 15;
      analysis.warnings.push(`Suspicious hosting provider: ${analysis.hostingProvider}`);
      this.detectionResults.suspiciousHosting = true;
    }

    // 5. Domain name analysis
    const domainAnalysis = this.analyzeDomainName(hostname);
    if (domainAnalysis.suspicious) {
      analysis.riskScore += domainAnalysis.riskScore;
      analysis.warnings.push(...domainAnalysis.warnings);
    }

    return analysis;
  }

  async checkDomainAge(hostname) {
    try {
      // Use WHOIS data via background script
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'checkDomainAge', domain: hostname },
          (response) => {
            if (chrome.runtime.lastError) {
              resolve(null);
              return;
            }
            resolve(response?.ageInDays || null);
          }
        );
      });
    } catch (error) {
      return null;
    }
  }

  async checkSSLValidity(hostname) {
    try {
      // Check if current page has valid SSL
      return window.location.protocol === 'https:' && 
             !document.querySelector('[src*="http:"]'); // Mixed content check
    } catch (error) {
      return false;
    }
  }

  async checkBlacklists(hostname) {
    try {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'checkBlacklists', domain: hostname },
          (response) => {
            if (chrome.runtime.lastError) {
              resolve([]);
              return;
            }
            resolve(response?.blacklists || []);
          }
        );
      });
    } catch (error) {
      return [];
    }
  }

  async analyzeHostingProvider(hostname) {
    try {
      // Get IP and hosting info via background script
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: 'analyzeHosting', domain: hostname },
          (response) => {
            if (chrome.runtime.lastError) {
              resolve('unknown');
              return;
            }
            resolve(response?.hostingProvider || 'unknown');
          }
        );
      });
    } catch (error) {
      return 'unknown';
    }
  }

  analyzeDomainName(hostname) {
    const result = {
      suspicious: false,
      riskScore: 0,
      warnings: []
    };

    // Check for hyphens (common in scam domains)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 2) {
      result.riskScore += 10;
      result.warnings.push('Multiple hyphens in domain name');
      result.suspicious = true;
    }

    // Check for numbers in domain (except for legitimate cases)
    if (/\d{2,}/.test(hostname) && !/\b(360|24|7)\b/.test(hostname)) {
      result.riskScore += 10;
      result.warnings.push('Suspicious numbers in domain');
      result.suspicious = true;
    }

    // Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club'];
    const hasSuspiciousTLD = suspiciousTLDs.some(tld => hostname.endsWith(tld));
    if (hasSuspiciousTLD) {
      result.riskScore += 20;
      result.warnings.push('Suspicious TLD');
      result.suspicious = true;
    }

    // Check for domain hiding techniques
    if (hostname.includes('xn--')) {
      result.riskScore += 15;
      result.warnings.push('Punycode domain (possible homograph attack)');
      result.suspicious = true;
    }

    return result;
  }

  isSuspiciousHosting(hostingProvider) {
    const suspiciousProviders = [
      'bulletproof',
      'offshore',
      'anonymous',
      'freehost',
      '000webhost',
      'byethost'
    ];
    
    return suspiciousProviders.some(provider => 
      hostingProvider.toLowerCase().includes(provider)
    );
  }

  evaluateReputationResults(reputation, hostname) {
    if (reputation.riskScore >= 70) {
      this.triggerWarning(
        `🚨 HIGH RISK: This domain has poor reputation. ` +
        `Risk factors: ${reputation.warnings.join(', ')}. ` +
        `Avoid this site for donations.`,
        'high'
      );
      this.detectionResults.poorReputation = true;
    } else if (reputation.riskScore >= 40) {
      this.triggerWarning(
        `⚠️ CAUTION: This domain has some reputation issues. ` +
        `Concerns: ${reputation.warnings.join(', ')}. ` +
        `Verify legitimacy before donating.`,
        'medium'
      );
      this.detectionResults.poorReputation = true;
    }
  }

  hasDonationContent() {
    const text = document.body.innerText.toLowerCase();
    const donationKeywords = [
      'donate', 'donation', 'contribute', 'contribution', 'give now',
      'help jamaica', 'hurricane relief', 'emergency fund', 'disaster aid',
      'support victims', 'rebuild jamaica', 'melissa relief'
    ];
    
    const paymentKeywords = [
      'credit card', 'paypal', 'venmo', 'wire transfer', 'western union',
      'bank account', 'gift card', 'crypto', 'bitcoin'
    ];

    return donationKeywords.some(kw => text.includes(kw)) || 
           paymentKeywords.some(kw => text.includes(kw));
  }

  scanForSuspiciousForms() {
    const forms = document.querySelectorAll('form');
    let suspiciousForms = [];
    
    forms.forEach((form, index) => {
      const analysis = this.analyzeForm(form, index);
      if (analysis.riskLevel !== 'none') {
        suspiciousForms.push(analysis);
      }
    });

    if (suspiciousForms.length > 0 && !this.isTrustedDomain()) {
      this.handleSuspiciousForms(suspiciousForms);
    }
  }

  analyzeForm(form, index) {
    const analysis = {
      index,
      riskLevel: 'none',
      reasons: [],
      formText: form.innerText.toLowerCase(),
      action: (form.getAttribute('action') || '').toLowerCase()
    };

    // Check if this is a donation-related form
    const isDonationForm = /donat|contribut|give|support|help|relief|fund|pay now|donation/i.test(analysis.formText);
    
    if (!isDonationForm) return analysis;

    // Analyze risk factors
    const riskFactors = this.getFormRiskFactors(form, analysis);
    analysis.reasons = riskFactors.reasons;
    analysis.riskLevel = riskFactors.riskLevel;

    return analysis;
  }

  getFormRiskFactors(form, analysis) {
    const reasons = [];
    let riskLevel = 'low';

    // Check 1: External form submission to untrusted domains
    if (analysis.action && !analysis.action.includes(window.location.hostname)) {
      if (!this.isTrustedAction(analysis.action)) {
        reasons.push(`Form submits to external domain: ${analysis.action}`);
        riskLevel = 'medium';
      }
    }

    // Check 2: Payment fields on non-trusted domains
    const paymentFields = form.querySelectorAll(`
      input[type="credit"], 
      input[type="card"],
      input[name*="card"], 
      input[name*="cvv"], 
      input[name*="expir"],
      input[name*="number"],
      input[name*="credit"],
      select[name*="payment"],
      input[name*="account"]
    `);

    if (paymentFields.length > 0 && !this.isTrustedDomain()) {
      reasons.push(`Contains ${paymentFields.length} payment field(s)`);
      riskLevel = riskLevel === 'medium' ? 'high' : 'medium';
    }

    // Check 3: Excessive personal information
    const sensitiveFields = form.querySelectorAll(`
      input[type="password"],
      input[name*="ssn"],
      input[name*="social"],
      input[name*="birth"],
      input[name*="driver"],
      input[name*="passport"]
    `);

    if (sensitiveFields.length > 2) {
      reasons.push(`Requests excessive personal information (${sensitiveFields.length} fields)`);
      riskLevel = 'high';
    }

    // Check 4: Urgency language in form
    const urgencyKeywords = ['urgent', 'immediate', 'now', 'quick', 'instant', 'emergency'];
    const hasUrgency = urgencyKeywords.some(keyword => analysis.formText.includes(keyword));
    
    if (hasUrgency) {
      reasons.push('Uses urgency language to pressure donors');
      riskLevel = riskLevel === 'high' ? 'high' : 'medium';
    }

    return { reasons, riskLevel };
  }

  isTrustedAction(actionUrl) {
    // Trusted payment processors and official domains
    const trustedEndpoints = [
      'paypal.com',
      'stripe.com',
      'squareup.com',
      'venmo.com',
      'supportjamaica.gov.jm',
      '.gov.jm',
      'opm.gov.jm',
      'mof.gov.jm'
    ];

    // Also trust relative paths and same-domain submissions
    if (!actionUrl || actionUrl.startsWith('#') || actionUrl.startsWith('/') || 
        actionUrl.includes(window.location.hostname)) {
      return true;
    }

    return trustedEndpoints.some(trusted => actionUrl.includes(trusted));
  }

  isTrustedDomain() {
    const hostname = window.location.hostname.toLowerCase();
    
    // Official Jamaican government domains
    if (hostname.endsWith('.gov.jm')) {
      return true;
    }

    // Specifically trusted domains from our list
    if (this.trustedDomains.includes(hostname)) {
      return true;
    }

    // The official donation portal
    if (hostname === 'supportjamaica.gov.jm') {
      return true;
    }

    return false;
  }

  handleSuspiciousForms(suspiciousForms) {
    const highRiskForms = suspiciousForms.filter(form => form.riskLevel === 'high');
    const mediumRiskForms = suspiciousForms.filter(form => form.riskLevel === 'medium');
    
    if (highRiskForms.length > 0) {
      this.triggerWarning(
        `🚨 HIGH RISK: This page contains ${highRiskForms.length} suspicious donation form(s). ` +
        `Do NOT enter payment information. Use official portal: ${this.config.officialPortal}`,
        'high'
      );
    } else if (mediumRiskForms.length > 0) {
      this.triggerWarning(
        `⚠️ CAUTION: This page contains donation forms with potential issues. ` +
        `Verify this is a legitimate organization before proceeding.`,
        'medium'
      );
    }
    
    this.detectionResults.suspiciousForm = true;
    this.logFormAnalysis(suspiciousForms);
  }

  logFormAnalysis(forms) {
    console.log('Jamaica Donation Guard - Form Analysis:', {
      url: window.location.href,
      forms: forms,
      trusted: this.isTrustedDomain()
    });
  }

  // scanForScamContent() {
  //   const text = document.body.innerText.toLowerCase();
  //   const scamPatterns = [
  //     'urgent', 'immediate', 'act now', 'last chance', 'limited time',
  //     'send money now', 'wire transfer', 'gift cards only',
  //     'crypto donations', 'bitcoin accepted', 'western union'
  //   ];

  //   if (scamPatterns.some(pattern => text.includes(pattern)) && 
  //       !this.isTrustedDomain()) {
  //     this.triggerWarning(
  //       `💡 ALERT: This page uses urgency tactics common in donation scams. ` +
  //       `Legitimate relief efforts don't pressure donors with limited-time offers.`,
  //       'low'
  //     );
  //     this.detectionResults.scamContent = true;
  //   }
  // }

  calculateSimilarity(str1, str2) {
    // Remove www and common TLDs for better comparison
    const clean1 = str1.replace(/^www\.|\.com|\.org|\.net|\.gov\.jm/g, '');
    const clean2 = str2.replace(/^www\.|\.com|\.org|\.net|\.gov\.jm/g, '');
    
    // Simple Levenshtein-based similarity
    const matrix = [];
    for (let i = 0; i <= clean1.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= clean2.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= clean1.length; i++) {
      for (let j = 1; j <= clean2.length; j++) {
        const cost = clean1[i - 1] === clean2[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }
    const distance = matrix[clean1.length][clean2.length];
    return 1 - distance / Math.max(clean1.length, clean2.length);
  }

  triggerWarning(message, level = 'medium') {
    if (this.warningShown && this.config.maxWarnings <= 1) return;
    this.warningShown = true;

    this.showWarningOverlay(message, level);
    this.logDetection(message, level);
  }

  showWarningOverlay(message, level) {
    // Remove existing warning
    const existing = document.getElementById('jdg-warning');
    if (existing) existing.remove();

    const warning = document.createElement('div');
    warning.id = 'jdg-warning';
    warning.innerHTML = `
      <div class="jdg-warning-content jdg-${level}">
        <div class="jdg-header">
          <span class="jdg-icon">${this.getIcon(level)}</span>
          <strong class="jdg-title">Jamaica Donation Guard</strong>
          <button class="jdg-close" id="jdg-close">×</button>
        </div>
        <div class="jdg-message">${this.escapeHtml(message)}</div>
        <div class="jdg-reputation" id="jdg-reputation"></div>
        <div class="jdg-actions">
          <a href="https://${this.config.officialPortal}" target="_blank" class="jdg-btn jdg-primary">
            🌐 Official Portal
          </a>
          <a href="https://opm.gov.jm/jamaica-cyber-incident-response-team-issues-urgent-warning-about-fraudulent-hurricane-melissa-donation-websites/" 
             target="_blank" class="jdg-btn jdg-secondary">
            📢 JaCIRT Warning
          </a>
          <button class="jdg-btn jdg-report" id="jdg-report">
            🚨 Report This Site
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(warning);
    this.injectStyles();

    // Add reputation details if available
    this.addReputationDetails(warning);

    // Add event listeners
    const closeBtn = document.getElementById('jdg-close');
    const reportBtn = document.getElementById('jdg-report');
    
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        warning.remove();
      });
    }
    
    if (reportBtn) {
      reportBtn.addEventListener('click', () => {
        this.reportSite();
      });
    }
  }

  addReputationDetails(warning) {
    const reputationDiv = warning.querySelector('#jdg-reputation');
    if (!reputationDiv) return;

    const hostname = window.location.hostname;
    const reputation = this.domainReputationCache.get(hostname);
    
    if (reputation && reputation.warnings.length > 0) {
      reputationDiv.innerHTML = `
        <div class="jdg-reputation-details">
          <strong>Reputation Issues:</strong>
          <ul>
            ${reputation.warnings.map(warning => `<li>${this.escapeHtml(warning)}</li>`).join('')}
          </ul>
          <div class="jdg-risk-score">Risk Score: ${reputation.riskScore}/100</div>
        </div>
      `;
    }
  }

  getIcon(level) {
    const icons = {
      high: '🚨',
      medium: '⚠️',
      low: '💡'
    };
    return icons[level] || '⚠️';
  }

  injectStyles() {
    if (document.getElementById('jdg-styles')) return;

    const styles = `
      #jdg-warning {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        max-width: 450px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        animation: jdgSlideIn 0.3s ease-out;
      }

      @keyframes jdgSlideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }

      .jdg-warning-content {
        background: white;
        border-radius: 12px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        overflow: hidden;
        border-left: 6px solid;
      }

      .jdg-high { border-left-color: #d32f2f; }
      .jdg-medium { border-left-color: #ff9800; }
      .jdg-low { border-left-color: #2196f3; }

      .jdg-header {
        display: flex;
        align-items: center;
        padding: 12px 16px;
        background: #f8f9fa;
        border-bottom: 1px solid #dee2e6;
      }

      .jdg-icon { font-size: 20px; margin-right: 8px; }
      .jdg-title { flex: 1; font-size: 14px; font-weight: 600; color: #333; }
      .jdg-close { 
        background: none; 
        border: none; 
        font-size: 20px; 
        cursor: pointer; 
        color: #666; 
        padding: 0;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .jdg-close:hover { color: #333; }

      .jdg-message {
        padding: 16px;
        font-size: 13px;
        line-height: 1.4;
        color: #333;
        background: white;
      }

      .jdg-reputation {
        padding: 0 16px;
        font-size: 12px;
      }

      .jdg-reputation-details {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 12px;
      }

      .jdg-reputation-details ul {
        margin: 8px 0;
        padding-left: 20px;
      }

      .jdg-reputation-details li {
        margin-bottom: 4px;
      }

      .jdg-risk-score {
        font-weight: 600;
        color: #856404;
        margin-top: 8px;
      }

      .jdg-actions {
        padding: 12px 16px;
        background: #f8f9fa;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .jdg-btn {
        padding: 8px 12px;
        border: none;
        border-radius: 6px;
        text-decoration: none;
        text-align: center;
        font-size: 12px;
        cursor: pointer;
        transition: all 0.2s;
        font-family: inherit;
      }

      .jdg-primary { background: #1976d2; color: white; }
      .jdg-secondary { background: #6c757d; color: white; }
      .jdg-report { background: #dc3545; color: white; }

      .jdg-btn:hover { opacity: 0.9; transform: translateY(-1px); }

      @media (max-width: 768px) {
        #jdg-warning {
          left: 10px;
          right: 10px;
          top: 10px;
          max-width: none;
        }
      }
    `;

    const styleElement = document.createElement('style');
    styleElement.id = 'jdg-styles';
    styleElement.textContent = styles;
    document.head.appendChild(styleElement);
  }

  async reportSite() {
    try {
      const hostname = window.location.hostname;
      const reputation = this.domainReputationCache.get(hostname);
      
      await chrome.runtime.sendMessage({
        type: 'reportSite',
        url: window.location.href,
        hostname: hostname,
        detectionResults: this.detectionResults,
        reputation: reputation
      });
      
      // Show confirmation
      const existingWarning = document.getElementById('jdg-warning');
      if (existingWarning) {
        const messageDiv = existingWarning.querySelector('.jdg-message');
        if (messageDiv) {
          messageDiv.innerHTML = '✅ Thank you for reporting! Jamaican authorities have been notified.';
        }
      }
    } catch (error) {
      co
      alert('Failed to report site. Please try again or contact JaCIRT directly.');
    }
  }

  async logDetection(message, level) {
    try {
      const hostname = window.location.hostname;
      const reputation = this.domainReputationCache.get(hostname);
      
      await chrome.runtime.sendMessage({
        type: 'logDetection',
        details: {
          url: window.location.href,
          hostname: hostname,
          message,
          level,
          timestamp: new Date().toISOString(),
          detectionResults: this.detectionResults,
          reputation: reputation
        }
      });
    } catch (error) {
 
      
    }
  }

  startContinuousMonitoring() {
    // Monitor for dynamic content changes
    setInterval(() => {
      if (!this.warningShown) {
        this.scanForSuspiciousForms();
        // this.scanForScamContent();
      }
    }, this.config.scanInterval);
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize the detector when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    const detector = new DonationGuardDetector();
    detector.initialize();
  });
} else {
  const detector = new DonationGuardDetector();
  detector.initialize();
}