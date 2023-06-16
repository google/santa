/// Copyright 2023 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

import SwiftUI

import santa_common_SNTFileAccessEvent

@available(macOS 13, *)
@objc public class SNTFileAccessMessageWindowViewFactory : NSObject {
  @objc public static func createWith(window: NSWindow, event: SNTFileAccessEvent, customMsg: NSAttributedString?) -> NSViewController {
    return NSHostingController(rootView:SNTFileAccessMessageWindowView(window:window, event:event, customMsg:customMsg)
      .frame(width:800, height:600))
  }
}

@available(macOS 13, *)
struct Property : View {
  var lbl: String
  var val: String

  var body: some View {
    let width: CGFloat? = 150

    HStack(spacing: 5) {
      Text(lbl + ":")
        .frame(width: width, alignment: .trailing)
        .lineLimit(1)
        .font(.system(size: 12, weight: .bold))
        .padding(Edge.Set.horizontal, 10)

      Text(val)
        .fixedSize(horizontal: false, vertical: true)
        .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
    }

  }
}

@available(macOS 13, *)
struct Event: View {
  let e: SNTFileAccessEvent

  var body: some View {
    VStack(spacing:10) {
      Property(lbl: "Path Accessed", val: e.accessedPath)
      Property(lbl: "Rule Name", val: e.ruleName)
      Property(lbl: "Rule Version", val: e.ruleVersion)

      Divider()
        .frame(width: 700)

      if let app = e.application {
        Property(lbl: "Application", val: app)
      }

      Property(lbl: "Name", val: (e.filePath as NSString).lastPathComponent)
      Property(lbl: "Path", val: e.filePath)
      Property(lbl: "Identifier", val: e.fileSHA256)
      Property(lbl: "Parent", val: e.parentName + " (" + e.ppid.stringValue + ")")
    }
  }
}

@available(macOS 13, *)
struct SNTFileAccessMessageWindowView: View {
  let window: NSWindow?
  let event: SNTFileAccessEvent?
  let customMsg: NSAttributedString?

  @State private var checked = false

  var body: some View {
    VStack(spacing:20.0) {
      Spacer()
      Text("Santa").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))

      if let msg = customMsg {
        Text(AttributedString(msg)).multilineTextAlignment(.center).padding(15.0)
      } else {
        Text("Access to a protected resource was denied.").multilineTextAlignment(.center).padding(15.0)
      }

      Event(e: event!)

      Toggle(isOn: $checked) {
        Text("Prevent future notifications for this application for a day")
          .font(Font.system(size: 11.0));
      }

      VStack(spacing:15) {
          Button(action: openButton, label: {
            Text("Open Event Info...").frame(maxWidth:.infinity)
          })
          Button(action: dismissButton, label: {
            Text("Dismiss").frame(maxWidth:.infinity)
          })
          .keyboardShortcut(.return)
      }.frame(width: 220)

      Spacer()

    }.frame(maxWidth:800.0).fixedSize()
  }

  func publisherInfo() {
    // TODO(mlw): Will hook up in a separate PR
    print("showing publisher popup...")
  }

  func openButton() {
    // TODO(mlw): Will hook up in a separate PR
    print("opening event info...")
  }

  func dismissButton() {
    window?.close()
    print("close window")
  }
}

@available(macOS 13, *)
func testFileAccessEvent() -> SNTFileAccessEvent {
  let faaEvent = SNTFileAccessEvent()

  faaEvent.accessedPath = "/accessed/path"
  faaEvent.ruleVersion = "watched_path.v1"
  faaEvent.ruleName = "watched_path"
  faaEvent.fileSHA256 = "b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670"
  faaEvent.filePath = "/Applications/gShoe.app/Contents/MacOS/gShoe"
  faaEvent.application = "gShoe"
  faaEvent.teamID = "EQHXZ8M8AV"
  faaEvent.signingID = "com.google.gShoe"
  faaEvent.executingUser = "nobody"
  faaEvent.pid = 456
  faaEvent.ppid = 123
  faaEvent.parentName = "gLauncher"

  return faaEvent
}

// Enable previews in Xcode.
@available(macOS 13, *)
struct SNTFileAccessMessageWindowView_Previews: PreviewProvider {
  static var previews: some View {
    SNTFileAccessMessageWindowView(window: nil, event: testFileAccessEvent(), customMsg: nil)
  }
}
