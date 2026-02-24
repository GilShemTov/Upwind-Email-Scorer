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
* **Weighted Risk Scoring & Explainability**: Aggregates all triggered signals into a final score (0-100%). The UI outputs a color-coded verdict and explicitly lists the "Reasons" for the score, providing full transparency to the user.
