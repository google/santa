window.onload = function() {

  // Hand off from Objective-C santaData method to Javascript SantaInfo JSON Object
  var santaInfo = JSON.parse(window.AppDelegate.santaData());

  // Table anchor point to populate the WebView's Santa data table
  var tableRef = document.getElementById('santa-data-table').getElementsByTagName('tbody')[0];
  
  // Pulls Santa Message from SantaData into WebView
  document.getElementById("santa-dialog").innerHTML = santaInfo['message'];
  
  // Organizes the way the data is displayed
  // Changing the order here will change the order in the WebView
  var santaReference = {
    'application': santaInfo['application'],
    'filename': santaInfo['filename'],
    'path': santaInfo['path'],
    'publisher': santaInfo['publisher'],
    'identifier': santaInfo['identifier'],
    'bundle identifier': santaInfo['bundle identifier'],
    'parent': santaInfo['parent'],
    'user': santaInfo['user']
  };

  // If a bundle hash is detected, the "Next Steps" button
  // will disappear until the bundle hash is completed
  if ("undefined" !== typeof santaInfo['bundle identifier']) {
    document.getElementById("next-steps-button").style.visibility = 'hidden';
  }
  
  for (var key in santaReference) {
    if ("undefined" !== typeof santaInfo[key]) {
      // instantiates a row in the table
      var dataRow = tableRef.insertRow(tableRef.rows.length);
      
      // instantiates a label/key cell for the table row
      var labelCell  = dataRow.insertCell(0);
      labelCell.className = "label unselectable";
      labelCell.style.verticalAlign = "middle";
      
      // instantiates a data/value cell for the table row
      var dataCell = dataRow.insertCell(1);
      dataCell.className = "label-content";

      // Handles the assigning of IDs for targets cells in the table
      if (key == "application") {
        dataCell.setAttribute("id", "application");
      } else if (key == "identifier") {
        dataCell.setAttribute("id", "identifier");
        dataCell.className = "sha1HashOutput";
      } else if (key == "bundle identifier" ) {
        dataCell.setAttribute("id", "bundle-identifier");
        document.getElementById("next-steps-button").disabled = false;
      } else if (key == "publisher") {
        labelCell.setAttribute("id", "publisher");
      } else if (key == "publisher" && santaInfo[key] == "Not code-signed") {
        dataCell.setAttribute("id", "publisher-not-signed");
      }

      // Adds the "i" button near Publisher to show
      // certificate information if available 
      if (key == "publisher" && santaInfo[key] != "Not code-signed") {
        var cell = document.getElementById("publisher");
        var img = document.createElement('img');
        img.className = "info-icon";
        img.setAttribute("onClick", "window.AppDelegate.showCertInfo();")
        img.src = "info.gif";
        cell.appendChild(img);
      }

      // Appends label/key name into the row
      var keyText  = document.createTextNode(capitilize(key));
      
      // Handles the values of select fields and how
      // they are displayed in the end result
      if (key == "parent") {
        var valueText = document.createTextNode(santaInfo[key] + " (" + santaInfo['pid']+")");
      } else if (key == "identifier") {
        var valueText = document.createTextNode(sha1HashFormatting(santaInfo[key]));
      } else if (key == "bundle identifier") {
        var cell = document.getElementById("bundle-identifier");
        var img = document.createElement('img');
        img.src = "loader.gif";
        cell.appendChild(img);
        var valueText = document.createTextNode("\n");
      } else {
        var valueText = document.createTextNode(santaInfo[key]);
      }

      // Appends labels and values to the tables anchor
      // for each loop iteration
      labelCell.appendChild(keyText);
      dataCell.appendChild(valueText);
    }
  }

  // Data-specific field modifications
  var bundleDiv = document.createElement("div");
  bundleDiv.setAttribute("id", "fileCountUpdate");
  var bundleIdentifierDiv = document.getElementById("bundle-identifier");
  bundleIdentifierDiv.appendChild(bundleDiv);
  document.getElementById("fileCountUpdate").innerHTML = "...";
}

// Detection of Notification Silencing and passes returned BOOL to Santa
function checkIgnore() {
  if (document.getElementById("ignore-checkbox").checked) {
    return true;
  } else {
    return false;
  }
}

// Handles Bundle Hashing string to show total files/binaries that
// have been scanned and formats it. Disappears after completition
function bundleHashChanged(bundleHash) {
  if (bundleHash == "(null)") {
    document.getElementById("bundle-identifier").innerHTML = "Could not calculate bundle hash";
  } else {
    document.getElementById("bundle-identifier").innerHTML = sha1HashFormatting(bundleHash);
  }
  document.getElementById("next-steps-button").style.visibility = 'visible';
  var dataCell = document.getElementById("bundle-identifier");
  dataCell.className = "sha1HashOutput";
}

// Capitalizes labels for each row detecting if two words are present
// and capitalizing based on what it is detected
function capitilize(string) {
  if (/\s/.test(string)) {
    var spaceIndex = string.indexOf(' ');
    var firstWord = string.charAt(0).toUpperCase() + string.slice(1, spaceIndex);
    var secondWord = string.charAt(spaceIndex + 1).toUpperCase() + 
      string.slice(spaceIndex + 2);
    return firstWord + " " + secondWord;
  } else {
    return string.charAt(0).toUpperCase() + string.slice(1);
  }
}

// Formats any hash-related output to the desired appearance
// splitting the hash in half for better readability
function sha1HashFormatting(str) {
  var formattedString = str.slice(0,str.length/2) + " \n " + str.slice(str.length/2);
  return formattedString;
}

// Takes in the bundle hash update string from Objective-C
// method and updates it in the WebView
function fileCountUpdateString(str) {
  document.getElementById("fileCountUpdate").innerHTML = str;
}