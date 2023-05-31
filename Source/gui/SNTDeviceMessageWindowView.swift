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

import santa_common_SNTConfigurator
import santa_common_SNTDeviceEvent

@objc public class SNTDeviceMessageWindowViewFactory : NSObject {
  @objc public static func createWith(window: NSWindow, event: SNTDeviceEvent, customMsg: NSAttributedString?) -> NSViewController {
    return NSHostingController(rootView:SNTDeviceMessageWindowView(window:window, event:event, customMsg:customMsg).frame(width:450, height:300))
  }
}

struct SNTDeviceMessageWindowView: View {
  let window: NSWindow?
  let event: SNTDeviceEvent?
  let customMsg: NSAttributedString?

  let c = SNTConfigurator()


  var body: some View {
    VStack(spacing:20.0) {
      Text("Santa").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))

      if let t = customMsg {
        if #available(macOS 12.0, *) {
          let a = AttributedString(t)
          Text(a).multilineTextAlignment(.center).padding(15.0)
        } else {
          Text(t.description).multilineTextAlignment(.center).padding(15.0)
        }
      } else {
        Text("Mounting devices is blocked")
      }

      HStack(spacing:5.0) {
        VStack(alignment: .trailing, spacing: 8.0) {
          Text("Device Name").bold()
          Text("Device BSD Path").bold()

          if event!.remountArgs?.count ?? 0 > 0 {
            Text("Remount Mode").bold()
          }
        }
        Spacer().frame(width: 10.0)
        VStack(alignment: .leading, spacing: 8.0) {
          Text(event!.mntonname)
          Text(event!.mntfromname)

          if event!.remountArgs?.count ?? 0 > 0 {
            Text(event!.readableRemountArgs())
          }
        }
      }

      HStack {
        Button(action: dismissButton) {
          Text("OK").frame(width: 90.0)
        }
        .keyboardShortcut(.defaultAction)

      }.padding(10.0)
    }
  }

  func dismissButton() {
    window?.close()
  }
}

// Enable previews in Xcode.
struct SNTDeviceMessageWindowView_Previews: PreviewProvider {
  static var previews: some View {
    SNTDeviceMessageWindowView(window: nil, event: nil, customMsg: nil)
  }
}

