
# 🇯🇲 Fake Donation Site Detector – Jamaica Cyberwatch

## 🛡️ Overview
The **Fake Donation Site Detector** Chrome extension helps protect Jamaicans from fraudulent donation websites—especially those exploiting national disasters like **Hurricane Melissa**.  
It was built in response to the **JaCIRT and OPM urgent advisory** warning citizens about **fake hurricane relief sites** masquerading as legitimate government or charity portals.

This extension checks each website you visit and warns you if it’s **suspicious**, **unverified**, or **potentially fraudulent**.

---

## 🚀 Features
- **Automatic Fraud Detection** – Compares sites you visit against known fake domains.
- **Trusted Source Verification** – Recognizes official Jamaican government and JaCIRT portals.
- **Heuristic Scanning** – Detects suspicious donation forms, urgent language, and scam-like patterns.
- **Real-Time Warnings** – Displays an on-page alert overlay when a site is unsafe.
- **Remote Configuration** – (optional) Updates domain lists from an official government JSON source.
- **Lightweight & Privacy-Safe** – No user data collection or tracking.

---

## 📦 Folder Structure
```
fake-donation-detector/
│
├── manifest.json
├── background.js
├── content-script.js
├── popup.html
├── popup.js
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── README.md
```

---

## ⚙️ Installation (Local Testing)
1. **Unzip** the extension folder (`fake-donation-detector.zip`).
2. Open Chrome and go to:  
   ```
   chrome://extensions
   ```
3. Turn on **Developer Mode** (top right corner).
4. Click **Load unpacked** → Select your extracted folder.
5. The extension icon (Jamaican shield + stop sign) will appear in your Chrome toolbar.

To test, visit:
```
https://melissareliefjamaica.net
```
You should see a **fraud warning overlay**.

---

## 🌐 Remote Management (Optional)
To update the trusted and suspicious domain lists remotely, host a JSON file:

coming soon


---


## 🧑‍💻 Developer Info
**Maintainer:** Kevonia Tomlinson

**License:** MIT License  
**Version:** 1.0.0  
**Manifest Version:** 3  

---

## 🔐 Security Notice
This extension does **not collect or transmit any personal data**.  
It only reads the **current website’s URL** and compares it against a public list of fraudulent or trusted domains.

---

## 🏛️ References
- [JaCIRT Advisory on Hurricane Melissa Donation Scams](https://opm.gov.jm/jamaica-cyber-incident-response-team-issues-urgent-warning-about-fraudulent-hurricane-melissa-donation-websites/)
- [Office of the Prime Minister (OPM) Jamaica](https://opm.gov.jm/)
- [JaCIRT Official Website](https://jacirt.gov.jm/)

---

**Protecting Jamaica’s Digital Future 🇯🇲**  
Together, we can stop online fraud before it spreads.
