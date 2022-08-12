#import <Cocoa/Cocoa.h>

@protocol SNTMessageWindowControllerDelegate
- (void)windowDidCloseSilenceHash:(NSString *)hash;
@end

@interface SNTMessageWindowController : NSWindowController

- (IBAction)showWindow:(id)sender;
- (IBAction)closeWindow:(id)sender;

/// Generate a distinct key for a given displayed event. This key is used for silencing future
/// notifications.
- (NSString *)messageHash;

///  Linked to checkbox in UI to prevent future notifications for the given event.
@property BOOL silenceFutureNotifications;

@property(weak) id<SNTMessageWindowControllerDelegate> delegate;

@end
