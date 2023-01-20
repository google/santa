import SwiftUI

import Source_common_SNTConfigurator

@objc public class SNTAboutWindowViewFactory : NSObject {
  @objc public static func createWith(window: NSWindow) -> NSViewController {
    return NSHostingController(rootView:SNTAboutWindowView(w:window).frame(width:400, height:200))
  }
}

struct SNTAboutWindowView: View {
  let w: NSWindow?
  let c = SNTConfigurator()

  var body: some View {
    VStack(spacing:20.0) {
      Text("Santa").font(Font.custom("HelveticaNeue-UltraLight", size: 34.0))

      if let t = c.aboutText {
        Text(t).multilineTextAlignment(.center)
      } else {
        Text("""
        Santa is an application control system for macOS.

        There are no user-configurable settings.
        """).multilineTextAlignment(.center)
      }

      HStack {
        if c.moreInfoURL?.absoluteString.isEmpty == false {
          Button(action: moreInfoButton) {
            Text("More Info...").frame(width: 90.0)
          }
        }

        Button(action: dismissButton) {
          Text("Dismiss").frame(width: 90.0)
        }
        .keyboardShortcut(.defaultAction)

      }.padding(10.0)
    }
  }

  func dismissButton() {
    w?.close()
  }

  func moreInfoButton() {
    if let u = c.moreInfoURL {
      NSWorkspace.shared.open(u)
    }
    w?.close()
  }
}

// Enable previews in Xcode.
struct SNTAboutWindow_Previews: PreviewProvider {
  static var previews: some View {
    SNTAboutWindowView(w: nil)
  }
}

