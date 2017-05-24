window.onload = function() {
  var santaInfo = JSON.parse(window.AppDelegate.santaData());
  var tableRef = document.getElementById('santa-data-table').getElementsByTagName('tbody')[0];

  document.getElementById("santa-dialog").innerHTML = santaInfo['message'];

  var santaReference = {
    'application': santaInfo['application'],
    'filename': santaInfo['filename'],
    'path': santaInfo['path'],
    'publisher': santaInfo['publisher'],
    'identifier': santaInfo['identifier'],
    'parent': santaInfo['parent'],
    'user': santaInfo['user']
  };  
  for (var key in santaReference) {
    if ("undefined" !== typeof santaInfo[key]) {
      // Insert a row in the table at the last row
      var dataRow   = tableRef.insertRow(tableRef.rows.length);
      
      // Insert a cell in the row at index 0
      var labelCell  = dataRow.insertCell(0);
      labelCell.className = "label unselectable";
      labelCell.style.verticalAlign = "middle";
      
      if (key == "publisher") {
        labelCell.setAttribute("id", "publisher");
      }
      
      var dataCell = dataRow.insertCell(1);
      dataCell.className = "label-content";

      if (key == "identifier") {
        dataCell.setAttribute("id", "identifier");
      }
      if (key == "application") {
        dataCell.setAttribute("id", "application");
      } else if (key == "publisher" && santaInfo[key] == "Not code-signed") {
        dataCell.setAttribute("id", "publisher-not-signed");
      }
      // Append a text node to the cell
      
      var keyText  = document.createTextNode(capitilize(key));
      if (key == "publisher" && santaInfo[key] != "Not code-signed") {
        var cell = document.getElementById("publisher");
        var img = document.createElement('img');
        img.className = "info-icon";
        img.setAttribute("onClick", "window.AppDelegate.showCertInfo();")
        img.src = "info.gif";
        cell.appendChild(img);
      }
      
      if (key == "parent") {
        var valueText = document.createTextNode(santaInfo[key] + " (" + santaInfo['pid']+")");
      } else if (key == "identifier") {
        var valueText = document.createTextNode(sha256Formatting(santaInfo[key]));
      } else {
        var valueText = document.createTextNode(santaInfo[key]);

      }
      labelCell.appendChild(keyText);
      dataCell.appendChild(valueText);
    }
  }
}

function checkIgnore() {
  if (document.getElementById("ignore-checkbox").checked) {
    return true;
  } else {
    return false;
  }
}

function publisherInfo() {
  console.log("Publisher");
}

function capitilize(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

function sha256Formatting(str) {
  var formattedString = str.slice(0,str.length/2) + " \n " + str.slice(str.length/2);
  return formattedString;
}