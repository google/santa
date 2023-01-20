#import "Source/gui/SNTMessageWindowController.h"

@implementation SNTMessageWindowController

- (IBAction)showWindow:(id)sender {
  [self.window setLevel:NSPopUpMenuWindowLevel];
  [self.window setMovableByWindowBackground:YES];
  [self.window makeKeyAndOrderFront:sender];
  [self.window center];
  [NSApp activateIgnoringOtherApps:YES];
}
- (IBAction)closeWindow:(id)sender {
  [self.window close];
}

- (void)windowWillClose:(NSNotification *)notification {
  if (!self.delegate) return;

  if (self.silenceFutureNotifications) {
    [self.delegate windowDidCloseSilenceHash:[self messageHash]];
  } else {
    [self.delegate windowDidCloseSilenceHash:nil];
  }
}

- (NSString *)messageHash {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

@end
