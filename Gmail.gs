/**
 * the primary function - takes data from an opened email and scores its maliciousness
 * @param e is the opened email that we want to score
 */

function onEmailPage(e){
  var messageId = e.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(messageId);
  var body = message.getPlainBody();
  var sender = message.getFrom();
  var attachments = message.getAttachments();

  var score = 0;
  var signals = [];
  var numOfSignals = 0;

  // check if the sender is in the blacklist
  if (checkIfBlaclisted(sender)){
    score += 50;
    numOfSignals++;
    signals.push("Sender is in the blacklist.");
  }

  // check if there is a malicious url in the mail content
  if (checkIfURLMalicious(body)){
    score += 50;
    numOfSignals++;
    signals.push("Malicious URL was found.")
  }

  // check if there are suspicious patterns in the email
  if (checkIfSusPatterns(body)){
    score += 10;
    numOfSignals++;
    signals.push("Urgent or threatening language was detected.");
  }

  // check if there are unsecured links
  if (checkIfHttp(body)){
    score += 10;
    numOfSignals++;
    signals.push("The email contains an unsecrued HTTP link.")
  }

  // check if a credit card was requested 
  if (checkIfCreditAsked(body)){
    score += 20;
    numOfSignals++;
    signals.push("Credit card information was requested.")
  }

  // check if attachments are double extensioned
  if (checkIfDoubleExtension(attachments)){
    score += 10;
    numOfSignals++;
    signals.push("Attachment has a suspicious double extension.")
  }

  // if there are more than one signal then the email is even more sus!
  score = Math.min(score*numOfSignals, 100);

  return createMaliciousScorerCard(score, signals);
}

/**
 * function to create the card 
 * @param score is the malisiousness score that was calculated
 * @param signals are the signals to show the user if there any
 * @returns the created malicious email scorer card
 */

function createMaliciousScorerCard(score, signals){
  var maliciousness = "";
  var color = "";

  if (score == 0){
    maliciousness = "✅ SAFE";
    color = "#34A853";
  }
  else if (score < 50){
    maliciousness = "⚠️ SUSPICIOUS";
    color = "#FBBC04";
  }
  else{
    maliciousness = "⛔ MALICIOUS";
    color = "#EA4335";
  }

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("<b>Maliciousness: <font color=\"" + color + "\">" + maliciousness + "</font></b>"))
    .addWidget(CardService.newTextParagraph().setText("Maliciousness Score: " + score + "%"));

  if (signals.length > 0){
    section.addWidget(CardService.newTextParagraph().setText("<b>Reasons:</b>\n• " + signals.join("\n• ")));
  }
  return CardService.newCardBuilder().addSection(section).build();
}

/**
 * on home page the side card just has a block where the user can add something to the blacklist.
 * @returns the card on home page where the user can add domains to the blacklist
 */

function onHomePage() {

  const section = CardService.newCardSection()

  section.addWidget(CardService.newTextInput()
    .setFieldName("new_entry")
    .setTitle("Add Domain to Blacklist"));

  section.addWidget(CardService.newTextButton()
    .setText("Update Blacklist")
    .setOnClickAction(CardService.newAction().setFunctionName("addToBlacklist")));

  return CardService.newCardBuilder().addSection(section).build();
}

/**
 * function that adds domains to the blacklist
 * returns a response if something was blacklisted
 */

function addToBlacklist(e){
  var sender = e.formInput.new_entry;

  if (!sender) return;
  
  var props = PropertiesService.getUserProperties();
  var blacklist = JSON.parse(props.getProperty('blacklist') || "[]");
  
  if (blacklist.indexOf(sender) === -1) {
    blacklist.push(sender);
    props.setProperty('blacklist', JSON.stringify(blacklist));
  }
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Added " + sender + " to blacklist."))
    .build();
}

/**
 * a function to check if something from the blacklist apears in the opened email
 * @param sender is the domain to check if is in the blacklist
 * @returns true if a sender is blacklisted and false otherwise
 */

function checkIfBlaclisted(sender){
  var props = PropertiesService.getUserProperties();
  var blacklist = JSON.parse(props.getProperty('blacklist') || "[]");
  return blacklist.some(item => sender.includes(item));
}

/**
 * a function to check whether the URLs or IPs from the opened email are malicious with external APIs
 * @param body is the content of the email to check if contains any malicious urls
 * @returns true if a url in the content of the email is malicious and false otherwise
 */

function checkIfURLMalicious(body) {
  var regex = /(?:https?:\/\/)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&//=]*)/gi;
  var urls = body.match(regex);
  
  if (!urls || urls.length === 0) return false;

  var apiKey = 'AIzaSyBikPlXknQT6C_vCBKAP0ttqjFqK_IXN5g';
  var apiUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + apiKey;

  // Format the URLs for the API payload, forcing 'http://' if it's missing
  var threatEntries = urls.map(function(url) {
    if (!url.startsWith('http')) {
      url = 'http://' + url;
    }
    return { "url": url };
  });


  // preparing the data the api needs
  var payload = {
    "client": {
      "clientId": "upwind-email-scorer",
      "clientVersion": "1.0"
    },
    "threatInfo": {
      "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      "platformTypes": ["ANY_PLATFORM"],
      "threatEntryTypes": ["URL"],
      "threatEntries": threatEntries
    }
  };

  var request = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true
  };

  // check the response
  try {
    var response = UrlFetchApp.fetch(apiUrl, request);
    var json = JSON.parse(response.getContentText());

    //if at least one of the urls is found malicious, return true
    if (json.matches && json.matches.length > 0) {
      return true;
    }
  } catch (e) {
    console.error("External API Call failed: " + e.toString());
  }
  return false; 
}

/**
 * a function that checks if there are suspicious patterns in the opened email
 * @param body is the content of the email to check if contains any suspicious patterns
 * @returns true if there are suspicious patterns in the email and false otherwise
 */

function checkIfSusPatterns(body){
  var regex = /(urgent|action required|verify your account|password expired|suspended)/gi;
  return regex.test(body);
}

/**
 * a function to check if there is an "http" link in the opened email
 * @param body is the content of the email to check if contains unsecured http link
 * @returns true if a http url was found and false otherwise
 */

function checkIfHttp(body){
  var regex = /http:\/\/[a-z0-9]/gi;
  return regex.test(body);
}

/**
 * function that checks if a credit card was asked
 * @param body is the content of the email to check if something related to credit cards is requested
 * @returns true if something related to credit card was asked and false otherwise
 */

function checkIfCreditAsked(body){
  var regex = /(credit card|cvv|expiry date|card number)/gi;
  return regex.test(body);
}

/**
 * a function to check if there is a double extensioned file
 * @param attachments are the attachments of the email to check if are double extensioned
 * @returns true if there is a double extensioned attachment and false otherwise
 */

function checkIfDoubleExtension(attachments){
  for (var i = 0; i < attachments.length; i++) {
    var name = attachments[i].getName();
    if (/\.[a-z]+\.[a-z]+$/i.test(name)) return true;
  }
  return false;  
}
