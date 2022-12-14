// Adapted from
// https://developer.apple.com/documentation/virtualization/running_macos_in_a_virtual_machine_on_apple_silicon_macs
/*
Copyright © 2022 Apple Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import "MacOSRestoreImage.h"

#import "Testing/integration/VM/Common/Error.h"

#import <Virtualization/Virtualization.h>

#ifdef __arm64__

@implementation MacOSRestoreImage

// MARK: Download the Restore Image from the network

- (void)downloadToBundle:(NSString *)bundleDir
   withCompletionHandler:(void (^)(NSURL *ipswURL))completionHandler {
  [VZMacOSRestoreImage
    fetchLatestSupportedWithCompletionHandler:^(VZMacOSRestoreImage *restoreImage, NSError *error) {
      if (error) {
        abortWithErrorMessage(
          [NSString stringWithFormat:@"Failed to fetch latest supported restore image catalog. %@",
                                     error.localizedDescription]);
      }

      NSLog(@"Attempting to download the latest available restore image.");
      NSURLSessionDownloadTask *downloadTask = [[NSURLSession sharedSession]
        downloadTaskWithURL:restoreImage.URL
          completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
            if (error) {
              abortWithErrorMessage(
                [NSString stringWithFormat:@"Failed to download restore image. %@",
                                           error.localizedDescription]);
            }

            NSURL *imageURL =
              [NSURL fileURLWithPath:[bundleDir stringByAppendingString:@"RestoreImage.ipsw"]];
            if (![[NSFileManager defaultManager] moveItemAtURL:location
                                                         toURL:imageURL
                                                         error:&error]) {
              abortWithErrorMessage(error.localizedDescription);
            }

            completionHandler(imageURL);
          }];

      [downloadTask.progress
        addObserver:self
         forKeyPath:@"fractionCompleted"
            options:NSKeyValueObservingOptionInitial | NSKeyValueObservingOptionNew
            context:nil];
      [downloadTask resume];
    }];
}

// MARK: Observe the download progress

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
  if ([keyPath isEqualToString:@"fractionCompleted"] && [object isKindOfClass:[NSProgress class]]) {
    NSProgress *progress = (NSProgress *)object;
    NSLog(@"Restore image download progress: %f.", progress.fractionCompleted * 100);

    if (progress.finished) {
      [progress removeObserver:self forKeyPath:@"fractionCompleted"];
    }
  }
}

@end

#endif
