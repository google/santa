/// Copyright 2015 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "SNTMessageWindow.h"

@interface SNTMessageWindow()
@property (assign) NSPoint initialLocation;
@end

@implementation SNTMessageWindow

- (BOOL)canBecomeKeyWindow {
  return YES;
}

- (BOOL)canBecomeMainWindow {
  return YES;
}

- (IBAction)fadeIn:(id)sender {
  [self setAlphaValue:0.f];
  [self center];
  [self makeKeyAndOrderFront:sender];
  [NSAnimationContext beginGrouping];
  [[NSAnimationContext currentContext] setDuration:0.15f];
  [[NSAnimationContext currentContext] setCompletionHandler:^{
    [NSApp activateIgnoringOtherApps:YES];
  }];
  [[self animator] setAlphaValue:1.f];
  [NSAnimationContext endGrouping];
}

- (IBAction)fadeOut:(id)sender {
  __weak __typeof(self) weakSelf = self;
  
  [NSAnimationContext beginGrouping];
  [[NSAnimationContext currentContext] setDuration:0.15f];
  [[NSAnimationContext currentContext] setCompletionHandler:^{
    [weakSelf.windowController windowWillClose:sender];
    [weakSelf orderOut:sender];
    [weakSelf setAlphaValue:1.f];
  }];
  [[self animator] setAlphaValue:0.f];
  [NSAnimationContext endGrouping];
}

- (void)sendEvent:(NSEvent *)event {
  switch (event.type) {
    case kCGEventLeftMouseDown:
      [self mouseDown:event];
    case kCGEventLeftMouseDragged:
      [self mouseDragged:event];
    default:
      [super sendEvent:event];
  }
}

- (void)mouseDown:(NSEvent *)theEvent {
  if ([[NSCursor currentCursor] isEqual:[NSCursor arrowCursor]]) {
    self.initialLocation = [theEvent locationInWindow];
  } else {
    self.initialLocation = NSZeroPoint;
  }
}


- (void)mouseDragged:(NSEvent *)theEvent {
  if (NSEqualPoints(self.initialLocation, NSZeroPoint)) return;
  NSPoint currentLocation = [NSEvent mouseLocation];;
  NSPoint newOrigin = NSMakePoint(currentLocation.x - self.initialLocation.x,
                                  currentLocation.y - self.initialLocation.y);
  
  // Don't let window get dragged up under the menu bar
  NSRect screenFrame = [[NSScreen mainScreen] frame];
  NSRect windowFrame = [self frame];
  if ((newOrigin.y + windowFrame.size.height) > (screenFrame.origin.y + screenFrame.size.height)) {
    newOrigin.y = screenFrame.origin.y + (screenFrame.size.height - windowFrame.size.height);
  }
  
  //go ahead and move the window to the new location
  [self setFrameOrigin:newOrigin];
}

@end
