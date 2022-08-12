#import "Source/gui/SNTMessageWindowController.h"

#import "Source/gui/SNTMessageWindow.h"

@implementation SNTMessageWindowController

- (IBAction)showWindow:(id)sender {
  [(SNTMessageWindow *)self.window fadeIn:sender];
}
- (IBAction)closeWindow:(id)sender {
  [(SNTMessageWindow *)self.window fadeOut:sender];
}

- (void)windowWillClose:(NSNotification *)notification {
  if (!self.delegate) return;

  if (self.silenceFutureNotifications) {
    [self.delegate windowDidCloseSilenceHash:[self messageHash]];
  } else {
    [self.delegate windowDidCloseSilenceHash:nil];
  }
}

- (void)loadWindow {
  [super loadWindow];
  [self.window setLevel:NSPopUpMenuWindowLevel];
  [self.window setMovableByWindowBackground:YES];
}

- (NSString *)messageHash {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

@end
