# Malicious Email Scorer
## Overview
The Malicious Email Scorer is a Google Workspace Gmail Add on designed to evaluate emails for phishing and threats.
It analyzes email content, attachments, URLs and sender in real time, calculating the risk and provides the user an explainable verdict.

## Architecture
The Add on was built on Google Apps Script platform.
* The Add on uses a contextual trigger (onEmailPage) that activates when the user opens an email.
* The Add on extracts the email metadata (sender, body, attachments) and passes it to functions in order to check several malicious options.
* User configuration is stored at the user level, so there is no need in external database.
* The cards are built and presented dynamically based on the maliciousness score.

## APIs Used
* **Gmail API** (GmailApp) is used to fetch the opened email metadata (sender, body, attachments).
* **Google Workspace CardService** is used to handle the visual presentation of the final score for each email, without needing to write HTTP or CSS.
* **Google PropertiesService** is used to persist the user's blacklist configuration.
* **UrlFetchApp** is used to execute requests to external threat sources.
* **Google Safe Browsing Api** is used as an external API for URL enrichment. It recieves URLs and checks if they apear on Google's updated lists of malicious sites.

## Implemented Features
* **Dynamic Enrichment via External APIs**: extracts URLs from the email amd send a request to the Safe Google API to detect known malicious links.
* **Static Heuristic Content Analysis**: uses Regular Expressions (Regex) to scan the email body for indicators, such as requests for credit card information, unsecured HTTP links, and urgent or threatening language typical of social engineering.
* **Attachment Sandboxing**: Scans the filenames of all attached files to detect suspicious double extensions (e.g., document.pdf.exe).
* **Weighted Risk Scoring & Explainability**: aggregates all triggered signals into a final score (0-100%). The score is calculated as the sum of scores multiplied by the number of triggered signals in order to give more weight to the maliciousness as the number of signals grows. The UI outputs the verdict and the reasons for the score, providing full transparency to the user.
* **User-Managed Blacklist**: arovides a home-page dashboard on the email card allowing users to manually block specific domains or email addresses.
* **Attachment Analysis**: analyzes attachments in order to identify potentially malicious caracteristics.

## Limitations
* **Regex Limitation**: hardcoded textual pattern matching can be bypassed by sophisticated threat actors using text obfuscation, zero-width spaces, or embedding text inside images. In addition, on this implementation of the Malicious Email Score, it is checked whether a credit card or something related is requested in the body of the email, so only a few related words are checked while there might be more options.
*  **Storage Scaling**: on this assignment the Malicious Email Scorer is implemented for a single user so the database is only local, but Ideally the database would be implemented generally for all Gmail users in order to share information and potentially malicious emails and domains.
*  **UI Limitation**: the application is bounded by the design of CardService. For example, dynamic styling (like changing the header's background's color according to the verdict) is restricted by the platform's API constraints.

## Examples
#### 1. Home Page Card For Adding To Blacklist

<img width="562" height="482" alt="צילום מסך 2026-02-24 194330" src="https://github.com/user-attachments/assets/2e2c3821-2b24-41b6-b74d-64a12b015aea" />

#### 2. 100% Scored Email For Having The Sender Blacklisted And Double Extensioned Attachment

<img width="1355" height="624" alt="צילום מסך 2026-02-24 194459" src="https://github.com/user-attachments/assets/ac174d4e-970e-4148-b5b5-8ae9e0565cdd" />

#### 3. 60% Scored Email For Requested Credit Card And Malicious Request ("verify your account")

<img width="1358" height="448" alt="צילום מסך 2026-02-24 194525" src="https://github.com/user-attachments/assets/bd57a09a-697e-49c1-b15a-e51374c84b34" />

#### 4. 100% Scored Email For Sending An Unsecured HTTP Link, A Malicious URL Found And A Blacklisted Sender

<img width="1428" height="590" alt="צילום מסך 2026-02-24 194602" src="https://github.com/user-attachments/assets/6dabf356-4c51-46fe-ac5e-0a1383acae43" />
