window.onload = function() {
  // Hands off from Objective-C santaData method to Javascript SantaInfo JSON Object
  var santaInfo = JSON.parse(window.AppDelegate.santaData());
  
  // Table anchor point to populate the WebView's Santa data table
  var tableRef = document.getElementById('santa-data-table').getElementsByTagName('tbody')[0];
  
  // Pulls Santa Message from SantaData into WebView
  document.getElementById("santa-dialog").innerHTML = santaInfo['message'];
  
  // Customize text when the binary has not been code-signed
  if (!('publisher' in santaInfo)) {
    santaInfo['publisher'] = "Not code-signed";
  }
  
  // Organizes the way the data is displayed
  // Changing the order here will change the order in the WebView
  var santaReference = {
    'Application': santaInfo['application'],
    'Filename': santaInfo['filename'],
    'Path': santaInfo['path'],
    'Publisher': santaInfo['publisher'],
    'Identifier': santaInfo['identifier'],
    'Bundle Identifier': santaInfo['bundle identifier'],
    'Parent': santaInfo['parent'],
    'User': santaInfo['user']
  };
  
  // If a bundle hash is detected, the "Next Steps" button
  // will disappear until the bundle hash is completed
  if (undefined !== santaReference['Bundle Identifier']) {
    document.getElementById("next-steps-button").disabled = true;
  }
  
  for (var key in santaReference) {
    if (undefined === santaReference[key]) {
      continue;
    }
    var keyLowerCase = key.toLowerCase().replace(/ /g, '-');
    
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
    switch(key) {
      case "Application":
        dataCell.setAttribute("id", keyLowerCase);
        break;
      case "Identifier":
        dataCell.setAttribute("id", keyLowerCase);
        dataCell.className = "shaHashOutput";
        break;
      case "Bundle Identifier":
        dataCell.setAttribute("id", keyLowerCase);
        break;
      case "Publisher":
        labelCell.setAttribute("id", keyLowerCase);
        if (key == "Publisher" && santaReference[key] == "Not code-signed") {
          dataCell.setAttribute("id", "publisher-not-signed");
        } else {
          var cell = document.getElementById("publisher");
          var img = document.createElement('img');
          img.className = "info-icon";
          img.setAttribute("onClick", "window.AppDelegate.showCertInfo();")
          img.src = "info.gif";
          cell.appendChild(img);
        }
        break;
    }
    
    // Appends label/key name into the row
    var keyText = document.createTextNode(key);
    
    // Handles the values of select fields and how
    // they are displayed in the end result
    switch(key) {
      case "Parent":
        var valueText = document.createTextNode(santaReference[key] + " (" + santaInfo['ppid']+")");
        break;
      case "Identifier":
        var valueText = document.createTextNode(shaHashFormatting(santaReference[key]));
        break;
      case "Bundle Identifier":
        var cell = document.getElementById("bundle-identifier");
        var progress = document.createElement("progress");
        progress.setAttribute("id", "progress-bar");
        cell.appendChild(progress);
        var valueText = document.createTextNode("\n");
        break;
      default:
        var valueText = document.createTextNode(santaReference[key]);
    }
    // Appends labels and values to the tables anchor
    // for each loop iteration
    labelCell.appendChild(keyText);
    dataCell.appendChild(valueText);
  }
  
  // Data-specific field modifications
  var bundleDiv = document.createElement("div");
  bundleDiv.setAttribute("id", "fileCountUpdate");
  var bundleIdentifierDiv = document.getElementById("bundle-identifier");
  bundleIdentifierDiv.appendChild(bundleDiv);
  document.getElementById("fileCountUpdate").innerHTML = "Initializing Calculation...";
}

// Detection of Notification Silencing and passes returned BOOL to Santa
function checkIgnore() {
  return document.getElementById("ignore-checkbox").checked;
}

// Handles Bundle Hashing string to show total files/binaries that
// have been scanned and formats it. Disappears after completition
function bundleHashChanged(bh) {
  document.getElementById("bundle-identifier").innerHTML =
  (bh == "(null)") ? "Could not calculate bundle hash" : shaHashFormatting(bh);
  document.getElementById("next-steps-button").disabled = false;
  var dataCell = document.getElementById("bundle-identifier").className = "shaHashOutput";
}

// Formats any hash-related output to the desired appearance
// splitting the hash in half for better readability
function shaHashFormatting(str) {
  return str.slice(0, str.length / 2) + " \n " + str.slice(str.length / 2);
}

// Takes in the bundle hash update string from Objective-C
// method and updates it in the WebView
function fileCountUpdateString(str) {
  // Customize this to show text while binary count is still initiating
  var calculationStatus = (str == "(null)") ? "Calculation Starting..." : str;
  document.getElementById("fileCountUpdate").innerHTML = calculationStatus;
}
