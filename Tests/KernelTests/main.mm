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

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/kext/KextManager.h>

#import <CommonCrypto/CommonDigest.h>

#include <cmath>
#include <ctime>
#include <iostream>
#include <libkern/OSKextLib.h>
#include <mach/mach.h>
#include <numeric>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <vector>

#include "SNTKernelCommon.h"

///
/// Kernel Extension Tests
///
/// Build and launch as root. This target is dependent on the santa-driver target and these
/// tests will load santa-driver from the same location this binary is executed from, unloading
/// any existing driver (and daemon) if necessary.
///

#define TSTART(testName) \
    do { printf("   %-50s ", testName); } while (0)
#define TPASS() \
    do { printf("PASS\n"); } while (0)
#define TPASSINFO(fmt, ...) \
    do { printf("PASS\n      " fmt "\n", ##__VA_ARGS__); } while (0)
#define TFAIL() \
    do { \
      printf("FAIL\n"); \
      [self unloadExtension]; \
      exit(1); \
    } while (0)
#define TFAILINFO(fmt, ...) \
    do { \
      printf("FAIL\n   -> " fmt "\n\nTest failed.\n\n", ##__VA_ARGS__); \
      [self unloadExtension]; \
      exit(1); \
    } while (0)

@interface SantaKernelTests : NSObject
@property io_connect_t connection;

// A block that tests can set to handle specific files/binaries.
// The block should return an action to respond to the kernel with.
// If no block is specified or no action is returned, the exec will be allowed.
@property(atomic, copy) santa_action_t (^handlerBlock)(santa_message_t msg);

- (void)unloadDaemon;
- (void)unloadExtension;
- (void)loadExtension;
- (void)runTests;
@end

@implementation SantaKernelTests

#pragma mark - Test Helpers

/// Return an initialized NSTask for |path| with stdout, stdin and stderr directed to /dev/null
- (NSTask *)taskWithPath:(NSString *)path {
  NSTask *t = [[NSTask alloc] init];
  t.launchPath = path;
  t.standardInput = nil;
  t.standardOutput = nil;
  t.standardError = nil;
  return t;
}

- (NSString *)sha256ForPath:(NSString *)path {
  unsigned char sha256[CC_SHA256_DIGEST_LENGTH];
  NSData *fData = [NSData dataWithContentsOfFile:path
                                         options:NSDataReadingMappedIfSafe
                                           error:nil];
  CC_SHA256([fData bytes], (unsigned int)[fData length], sha256);
  char buf[CC_SHA256_DIGEST_LENGTH * 2 + 1];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
    snprintf(buf + (2 * i), 4, "%02x", (unsigned char)sha256[i]);
  }
  buf[CC_SHA256_DIGEST_LENGTH * 2] = '\0';
  return @(buf);
}

/// Return the path to the version of ld being used by clang.
- (NSString *)ldPath {
  static NSString *path;
  if (!path) {
    NSTask *xcrun = [self taskWithPath:@"/usr/bin/xcrun"];
    xcrun.arguments = @[@"-f", @"ld"];
    xcrun.standardOutput = [NSPipe pipe];
    @try {
      [xcrun launch];
      [xcrun waitUntilExit];
    } @catch (NSException *exception) {
      return nil;
    }
    if (xcrun.terminationStatus != 0) return nil;
    NSData *data = [[xcrun.standardOutput fileHandleForReading] readDataToEndOfFile];
    if (!data) return nil;
    path = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
  }
  return path;
}

#pragma mark - Driver Helpers

/// Call in-kernel function: |kSantaUserClientAllowBinary| or |kSantaUserClientDenyBinary|
/// passing the |vnodeID|.
- (void)postToKernelAction:(santa_action_t)action forVnodeID:(santa_vnode_id_t)vnodeid {
  switch (action) {
    case ACTION_RESPOND_ALLOW:
      IOConnectCallStructMethod(self.connection, kSantaUserClientAllowBinary,
                                &vnodeid, sizeof(vnodeid), 0, 0);
      break;
    case ACTION_RESPOND_DENY:
      IOConnectCallStructMethod(self.connection, kSantaUserClientDenyBinary,
                                &vnodeid, sizeof(vnodeid), 0, 0);
      break;
    case ACTION_RESPOND_ACK:
      IOConnectCallStructMethod(self.connection, kSantaUserClientAcknowledgeBinary,
                                &vnodeid, sizeof(vnodeid), 0, 0);
      break;
    case ACTION_RESPOND_ALLOW_COMPILER:
      IOConnectCallStructMethod(self.connection, kSantaUserClientAllowCompiler,
                                &vnodeid, sizeof(vnodeid), 0, 0);
      break;
    default:
      TFAILINFO("postToKernelAction:forVnodeID: received unknown action type: %d", action);
      break;
  }
}

/// Call in-kernel function: |kSantaUserClientClearCache|
- (void)flushCache {
  uint64_t nonRootOnly = 0;
  IOConnectCallScalarMethod(self.connection, kSantaUserClientClearCache, &nonRootOnly, 1, 0, 0);
}

#pragma mark - Connection Tests

/// Tests the process of locating, attaching and opening the driver. Also verifies that the
/// driver correctly refuses non-privileged connections.
- (void)connectionTests {
  kern_return_t kr;
  io_service_t serviceObject;
  CFDictionaryRef classToMatch;

  TSTART("Creates matching service dictionary");
  if (!(classToMatch = IOServiceMatching(USERCLIENT_CLASS))) {
    TFAIL();
  }
  TPASS();

  TSTART("Locates Santa driver");
  serviceObject = IOServiceGetMatchingService(kIOMasterPortDefault, classToMatch);
  if (!serviceObject) {
    TFAILINFO("Is santa-driver.kext loaded?");
  }
  TPASS();

  TSTART("Driver refuses non-privileged connections");
  (void)setegid(-2);
  (void)seteuid(-2);
  kr = IOServiceOpen(serviceObject, mach_task_self(), 0, &_connection);
  if (kr != kIOReturnBadArgument) {
    TFAIL();
  }
  (void)setegid(0);
  (void)seteuid(0);
  TPASS();

  TSTART("Attaches to and starts Santa service");
  kr = IOServiceOpen(serviceObject, mach_task_self(), 0, &_connection);
  IOObjectRelease(serviceObject);
  if (kr != kIOReturnSuccess) {
    TFAILINFO("KR: %d", kr);
  }
  TPASS();

  TSTART("Calls 'open' method on driver");
  kr = IOConnectCallMethod(self.connection, kSantaUserClientOpen, 0, 0, 0, 0, 0, 0, 0, 0);

  if (kr == kIOReturnExclusiveAccess) {
    TFAILINFO("A client is already connected to the driver.\n"
              "Please kill the existing client and re-run the test.");
  } else if (kr != kIOReturnSuccess) {
    TFAILINFO("KR: %d", kr);
  }
  TPASS();

  TSTART("Refuses second client");
  kr = IOConnectCallMethod(self.connection, kSantaUserClientOpen, 0, 0, 0, 0, 0, 0, 0, 0);
  if (kr != kIOReturnExclusiveAccess) {
    TFAIL();
  }
  TPASS();
}

#pragma mark - Listener

/// Tests the process of allocating & registering a notification port and mapping shared memory.
/// From then on, monitors the IODataQueue and responds for files specifically used in other tests.
/// For everything else, allows execution normally to avoid deadlocking the system.
- (void)beginListening {
  TSTART("Allocates a notification port");
  mach_port_t receivePort;
  if (!(receivePort = IODataQueueAllocateNotificationPort())) {
    TFAIL();
  }
  TPASS();

  TSTART("Registers the notification port");
  kern_return_t kr = IOConnectSetNotificationPort(
      self.connection, QUEUETYPE_DECISION, receivePort, 0);
  if (kr != kIOReturnSuccess) {
    mach_port_destroy(mach_task_self(), receivePort);
    TFAILINFO("KR: %d", kr);
    return;
  }
  TPASS();

  TSTART("Maps shared memory");
  mach_vm_address_t address = 0;
  mach_vm_size_t size = 0;
  kr = IOConnectMapMemory(self.connection, QUEUETYPE_DECISION, mach_task_self(),
                          &address, &size, kIOMapAnywhere);
  if (kr != kIOReturnSuccess) {
    mach_port_destroy(mach_task_self(), receivePort);
    TFAILINFO("KR: %d", kr);
  }
  TPASS();

  /// Begin listening for events
  IODataQueueMemory *queueMemory = (IODataQueueMemory *)address;
  do {
    while (IODataQueueDataAvailable(queueMemory)) {
      santa_message_t vdata;
      UInt32 dataSize = sizeof(vdata);
      kr = IODataQueueDequeue(queueMemory, &vdata, &dataSize);
      if (kr != kIOReturnSuccess) {
        TFAILINFO("Error receiving data: %d", kr);
        continue;
      }
      if (vdata.action != ACTION_REQUEST_BINARY) continue;

      santa_action_t action = ACTION_RESPOND_ALLOW;

      @synchronized(self) {
        if (self.handlerBlock) action = self.handlerBlock(vdata);
      }

      [self postToKernelAction:action forVnodeID:vdata.vnode_id];
    }
  } while (IODataQueueWaitForAvailableData(queueMemory, receivePort) == kIOReturnSuccess);

  IOConnectUnmapMemory(self.connection, kIODefaultMemoryType, mach_task_self(), address);
  mach_port_destroy(mach_task_self(), receivePort);
}

#pragma mark - Functional Tests

- (void)receiveAndBlockTests {
  TSTART("Blocks denied binaries");

  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    if (strncmp("/bin/ed", msg.path, 7) == 0) return ACTION_RESPOND_DENY;
    return ACTION_RESPOND_ALLOW;
  };

  NSTask *ed = [self taskWithPath:@"/bin/ed"];
  @try {
    [ed launch];
    [ed waitUntilExit];
    TFAIL();
  }
  @catch (NSException *exception) {
    TPASS();
  }
}

- (void)receiveAndCacheTests {
  TSTART("Permits & caches allowed binaries");

  __block int timesSeenLs = 0;
  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    if (strncmp("/bin/ls", msg.path, 7) == 0) ++timesSeenLs;
    return ACTION_RESPOND_ALLOW;
  };

  NSTask *ls = [self taskWithPath:@"/bin/ls"];
  [ls launch];
  [ls waitUntilExit];

  if (timesSeenLs != 1) {
    TFAILINFO("Didn't record first run of ls");
  }

  ls = [self taskWithPath:@"/bin/ls"];
  [ls launch];
  [ls waitUntilExit];

  if (timesSeenLs > 1) {
    TFAILINFO("Received request for ls a second time");
  }

  TPASS();
}

- (void)invalidatesCacheTests {
  TSTART("Invalidates cache for manually closed FDs");

  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *target =
      [[fm currentDirectoryPath] stringByAppendingPathComponent:@"invalidatecachetest"];
  NSString *edSHA = [self sha256ForPath:@"/bin/ed"];

  __weak __typeof(self) weakSelf = self;
  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    __strong __typeof(weakSelf) self = weakSelf;
    if ([[self sha256ForPath:@(msg.path)] isEqual:edSHA]) {
      return ACTION_RESPOND_DENY;
    }
    return ACTION_RESPOND_ALLOW;
  };

  // Copy the pwd binary to a new file
  if (![fm copyItemAtPath:@"/bin/pwd" toPath:target error:nil]) {
    TFAILINFO("Failed to create temp file");
  }

  // Launch the new file to put it in the cache
  NSTask *pwd = [self taskWithPath:target];
  [pwd launch];
  [pwd waitUntilExit];

  // Exit if this fails with a useful message.
  if ([pwd terminationStatus] != 0) {
    TFAILINFO("First launch of test binary failed");
  }

  // Now replace the contents of the test file (which is cached) with the contents of /bin/ed,
  // which is 'blacklisted' by SHA-256 during the tests.
  FILE *infile = fopen("/bin/ed", "r");
  FILE *outfile = fopen(target.UTF8String, "w");
  int ch;
  while ((ch = fgetc(infile)) != EOF) {
    fputc(ch, outfile);
  }
  fclose(infile);

  // Now try running the temp file again. If it succeeds, the test failed.
  NSTask *ed = [self taskWithPath:target];

  @try {
    [ed launch];
    [ed waitUntilExit];
    TFAILINFO("Launched after write while file open");
    [fm removeItemAtPath:target error:nil];
  } @catch (NSException *exception) {
    // This is a pass, but we have more to do.
  }

  // Close the file to flush the write.
  fclose(outfile);

  // And try running the temp file again. If it succeeds, the test failed.
  ed = [self taskWithPath:target];

  @try {
    [ed launch];
    [ed waitUntilExit];
    TFAILINFO("Launched after file closed");
  } @catch (NSException *exception) {
    TPASS();
  } @finally {
    [fm removeItemAtPath:target error:nil];
  }
}

- (void)invalidatesCacheAutoCloseTest {
  TSTART("Invalidates cache for auto closed FDs");

  NSString *edSHA = [self sha256ForPath:@"/bin/ed"];

  __weak __typeof(self) weakSelf = self;
  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    __strong __typeof(weakSelf) self = weakSelf;
    if ([[self sha256ForPath:@(msg.path)] isEqual:edSHA]) {
      return ACTION_RESPOND_DENY;
    }
    return ACTION_RESPOND_ALLOW;
  };

  // Create temporary file
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm copyItemAtPath:@"/bin/pwd" toPath:@"invalidacachetest_tmp" error:nil]) {
    TFAILINFO("Failed to create temp file");
  }

  // Launch the new file to put it in the cache
  NSTask *pwd = [self taskWithPath:@"invalidacachetest_tmp"];
  [pwd launch];
  [pwd waitUntilExit];
  if ([pwd terminationStatus] != 0) {
    TFAILINFO("Second launch of test binary failed");
  }

  // Replace file contents using dd, which doesn't close FDs
  NSDictionary *attrs = [fm attributesOfItemAtPath:@"/bin/ed" error:NULL];
  NSTask *dd = [self taskWithPath:@"/bin/dd"];
  dd.arguments = @[ @"if=/bin/ed",
                    @"of=invalidacachetest_tmp",
                    @"bs=1",
                    [NSString stringWithFormat:@"count=%@", attrs[NSFileSize]]
  ];
  [dd launch];
  [dd waitUntilExit];

  // And try running the temp file again. If it succeeds, the test failed.
  NSTask *ed = [self taskWithPath:@"invalidacachetest_tmp"];
  @try {
    [ed launch];
    [ed waitUntilExit];
    TFAILINFO("Launched after file closed");
  } @catch (NSException *exception) {
    TPASS();
  } @finally {
    [fm removeItemAtPath:@"invalidacachetest_tmp" error:nil];
  }
}

- (void)clearCacheTests {
  TSTART("Can clear cache");

  __block int timesSeenCat = 0;
  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    if (strncmp("/bin/cat", msg.path, 8) == 0) ++timesSeenCat;
    return ACTION_RESPOND_ALLOW;
  };

  NSTask *cat = [self taskWithPath:@"/bin/cat"];
  [cat launch];
  [cat waitUntilExit];

  if (timesSeenCat != 1) {
    TFAILINFO("Didn't record first run of cat");
  }

  [self flushCache];

  cat = [self taskWithPath:@"/bin/cat"];
  [cat launch];
  [cat waitUntilExit];

  if (timesSeenCat != 2) {
    TFAIL();
  }

  TPASS();
}

- (void)blocksDeniedTracedBinaries {
  TSTART("Denies blocked processes running while traced");

  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    if (strncmp("/bin/mv", msg.path, 7) == 0) return ACTION_RESPOND_DENY;
    return ACTION_RESPOND_ALLOW;
  };

  pid_t pid = fork();
  if (pid < 0) {
    TFAILINFO("Failed to fork");
  } else if (pid > 0) {
    int status;
    while (waitpid(pid, &status, 0) != pid); // handle EINTR
    if (WIFEXITED(status) && WEXITSTATUS(status) == EPERM) {
      TPASS();
    } else if (WIFSTOPPED(status)) {
      TFAILINFO("Process was executed and is waiting for debugger");
    } else {
      TFAILINFO("Process did not exit with EPERM as expected");
    }
  } else if (pid == 0) {
    fclose(stdout);
    fclose(stderr);
    ptrace(PT_TRACE_ME, 0, 0, 0);
    execl("/bin/mv", "mv", NULL);
    _exit(errno);
  }
}

- (void)testCachePerformance {
  TSTART("Test cache performance...");

  // Execute echo 100 times, saving the time taken for each run
  std::vector<double> times;
  for (int i = 0; i < 100; ++i) {
    NSTask *t = [[NSTask alloc] init];
    t.launchPath = @"/bin/echo";
    t.standardOutput = [NSPipe pipe];
    auto start = std::chrono::steady_clock::now();
    [t launch];
    [t waitUntilExit];
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (i > 5) times.push_back(duration);
  }

  // Sort and remove first 10 and last 10 entries.
  std::sort(times.begin(), times.end());
  times.erase(times.begin(), times.begin()+10);
  times.erase(times.end()-10, times.end());

  // Calculate mean
  double mean = std::accumulate(times.begin(), times.end(), 0.0) / times.size();

  // Calculate stdev
  double accum = 0.0;
  std::for_each(times.begin(), times.end(), [&](const double d) {
    accum += (d - mean) * (d - mean);
  });
  double stdev = sqrt(accum / (times.size() - 1));

  if (mean > 80 || stdev > 10) {
    TFAILINFO("ms: %-3.2f σ: %-3.2f", mean, stdev);
  } else {
    TPASSINFO("ms: %-3.2f σ: %-3.2f", mean, stdev);
  }
}

- (void)testLargeBinary {
  TSTART("Handles large binary...");

  __block int calCount = 0;
  __weak __typeof(self) weakSelf = self;
  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    __strong __typeof(weakSelf) self = weakSelf;
    if (strncmp("/usr/bin/cal", msg.path, 12) == 0) {
      if (calCount++) TFAILINFO("Large binary should not re-request");
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
                     dispatch_get_global_queue(0, 0), ^{
        [self postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:msg.vnode_id];
      });
      return ACTION_RESPOND_ACK;
    }
    return ACTION_RESPOND_ALLOW;
  };

  @try {
    NSTask *testexec = [self taskWithPath:@"/usr/bin/cal"];
    [testexec launch];
    int sleepCount = 0;
    while ([testexec isRunning]) {
      sleep(1);
      if (++sleepCount > 5) TFAILINFO("Took longer than expected to start/stop");
    }
  } @catch (NSException *e) {
    TFAILINFO("Failed to launch");
  }

  TPASS();
}

- (void)testPendingTransitiveRules {
  TSTART("Adds pending transitive whitelist rules");

  NSString *ldPath = [self ldPath];
  if (!ldPath) {
    TFAILINFO("Couldn't get path to ld");
  }

  // Clear out cached decisions from any previous tests.
  [self flushCache];

  __block int ldCount = 0;
  __block int helloCount = 0;
  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    if (!strcmp(ldPath.UTF8String, msg.path)) {
      ldCount++;
      return ACTION_RESPOND_ALLOW_COMPILER;
    } else if (!strcmp("/private/tmp/hello", msg.path)) {
      helloCount++;
      return ACTION_RESPOND_DENY;
    }
    return ACTION_RESPOND_ALLOW;
  };
  // Write source file to /tmp/hello.c
  FILE *out = fopen("/tmp/hello.c", "wb");
  fprintf(out, "#include <stdio.h>\nint main(void) { printf(\"Hello, world!\\n\"); }");
  fclose(out);
  // Then compile it with clang and ld, the latter of which has been marked as a compiler.
  NSTask *clang = [self taskWithPath:@"/usr/bin/clang"];
  clang.arguments = @[@"-o", @"/private/tmp/hello", @"/private/tmp/hello.c"];
  [clang launch];
  [clang waitUntilExit];
  // Make sure that our version of ld marked as compiler was run.  This assumes that
  // "xcode-select -p" returns "/Applications/Xcode.app/Contents/Developer"
  if (ldCount != 1) {
    TFAILINFO("Didn't record run of ld");
  }
  // Check if we can now run /private/tmp/hello.  If working correctly, there will already be
  // a pending transitive rule in the cache, so no decision request will be sent to listener.
  // If for some reason a decision request is sent, then binary will be denied.
  NSTask *hello = [self taskWithPath:@"/private/tmp/hello"];
  @try {
    [hello launch];
    [hello waitUntilExit];
  } @catch (NSException *exception) {
    TFAILINFO("could not launch /private/tmp/hello: %s", exception.reason.UTF8String);
  }
  // Check that the listener was not consulted for the decision.
  if (helloCount > 0) {
    TFAILINFO("pending decision for /private/tmp/hello was not in cache");
  }

  // Clean up
  remove("/tmp/hello");
  remove("/tmp/hello.c");

  TPASS();
}

- (void)testNoTransitiveRules {
  TSTART("No transitive rule generated by non-compiler");

  NSString *ldPath = [self ldPath];
  if (!ldPath) {
    TFAILINFO("Couldn't get path to ld");
  }

  // Clear out cached decisions from any previous tests.
  [self flushCache];

  __block int ldCount = 0;
  __block int helloCount = 0;
  self.handlerBlock = ^santa_action_t(santa_message_t msg) {
    if (!strcmp(ldPath.UTF8String, msg.path)) {
      ldCount++;
      return ACTION_RESPOND_ALLOW;
    } else if (!strcmp("/private/tmp/hello", msg.path)) {
      helloCount++;
      return ACTION_RESPOND_DENY;
    }
    return ACTION_RESPOND_ALLOW;
  };
  // Write source file to /tmp/hello.c
  FILE *out = fopen("/tmp/hello.c", "wb");
  fprintf(out, "#include <stdio.h>\nint main(void) { printf(\"Hello, world!\\n\"); }");
  fclose(out);
  // Then compile it with clang and ld, neither of which have been marked as a compiler.
  NSTask *clang = [self taskWithPath:@"/usr/bin/clang"];
  clang.arguments = @[@"-o", @"/private/tmp/hello", @"/private/tmp/hello.c"];
  @try {
    [clang launch];
    [clang waitUntilExit];
  } @catch (NSException *exception) {
    TFAILINFO("Couldn't launch clang");
  }
  // Make sure that our version of ld was run.  This assumes that "xcode-select -p"
  // returns "/Applications/Xcode.app/Contents/Developer"
  if (ldCount != 1) {
    TFAILINFO("Didn't record run of ld");
  }
  // Check that we cannot run /private/tmp/hello.
  NSTask *hello = [self taskWithPath:@"/private/tmp/hello"];
  @try {
    [hello launch];
    [hello waitUntilExit];
    TFAILINFO("Should not have been able to launch /private/tmp/hello");
  } @catch (NSException *exception) {
    // All good
  }
  // Check that there wasn't a decision for /private/tmp/hello in the cache.
  if (helloCount != 1) {
    TFAILINFO("decision for /private/tmp/hello found in cache");
  }

  // Clean up
  remove("/tmp/hello");
  remove("/tmp/hello.c");

  TPASS();
}

- (void)testFilemodPrefixFilter {
  TSTART("Testing filemod prefix filter");

  NSString *filter =
      @"Albert Einstein, in his theory of special relativity, determined that the laws of physics "
      @"are the same for all non-accelerating observers, and he showed that the speed of light "
      @"within a vacuum is the same no matter the speed at which an observer travels.";

  // Create a buffer that has 1024 bytes of characters, non-terminating.
  char buffer[MAXPATHLEN + 1];  // +1 is for the null byte from strlcpy(). It falls off the ledge.
  for (int i = 0; i < 4; ++i) {
    if (![filter getFileSystemRepresentation:buffer + (i * filter.length) maxLength:MAXPATHLEN]) {
      TFAILINFO("Invalid filemod prefix filter: %s", filter.UTF8String);
    }
  }
  strlcpy(&buffer[1016], "E = mc²", 9);  // Fill in the last 8 bytes.

  uint64_t n = 0;
  uint32_t n_len = 1;

  // The filter should currently be empty. It is reset when the client disconnects.
  // Fill up the 1024 node capacity.
  kern_return_t ret =
  IOConnectCallMethod(self.connection, kSantaUserClientFilemodPrefixFilterAdd, NULL, 0, buffer,
                      sizeof(const char[MAXPATHLEN]), &n, &n_len, NULL, NULL);

  if (ret != kIOReturnSuccess || n != 1024) {
    TFAILINFO("Failed to fill the prefix filter: got %llu nodes expected 1024", n);
  }

  // Make sure it will enforce capacity.
  const char *too_much = "B";
  ret = IOConnectCallMethod(self.connection, kSantaUserClientFilemodPrefixFilterAdd, NULL, 0,
                            too_much, sizeof(const char[MAXPATHLEN]), &n, &n_len, NULL, NULL);
  if (ret != kIOReturnNoResources || n != 1024) {
    TFAILINFO("Failed enforce capacity: got %llu nodes expected 1024", n);
  }

  // Make sure it will prune.
  const char *ignore_it_all = "A";
  ret = IOConnectCallMethod(self.connection, kSantaUserClientFilemodPrefixFilterAdd, NULL, 0,
                            ignore_it_all, sizeof(const char[MAXPATHLEN]), &n, &n_len, NULL, NULL);
  // Expect 1 "A" node.
  if (ret != kIOReturnSuccess || n != 1) {
    TFAILINFO("Failed to prune the prefix filter: got %llu nodes expected 1", n);
  }

  // Reset.
  IOConnectCallScalarMethod(self.connection, kSantaUserClientFilemodPrefixFilterReset, NULL, 0,
                            NULL, NULL);

  // And fill it back up again.
  ret = IOConnectCallMethod(self.connection, kSantaUserClientFilemodPrefixFilterAdd, NULL, 0,
                            buffer, sizeof(const char[MAXPATHLEN]), &n, &n_len, NULL, NULL);

  if (ret != kIOReturnSuccess || n != 1024) {
    TFAILINFO("Failed to fill the prefix filter: got %llu nodes expected 1024", n);
  }

  TPASS();
}

#pragma mark - Main

- (void)unloadDaemon {
  NSTask *t = [[NSTask alloc] init];
  t.launchPath = @"/bin/launchctl";
  t.arguments = @[ @"remove", @"com.google.santad" ];
  t.standardOutput = t.standardError = [NSPipe pipe];
  [t launch];
  [t waitUntilExit];
}

- (void)unloadExtension {
  // Don't check the status of this, the kext may not be loaded..
  OSStatus ret = KextManagerUnloadKextWithIdentifier(CFSTR("com.google.santa-driver"));
  if (ret != kOSReturnSuccess && ret != kOSKextReturnNotFound) {
    NSLog(@"Failed to unload extension: 0x%X", ret);
  }
}

- (void)loadExtension {
  TSTART("Loads extension");

  NSError *error;
  NSFileManager *fm = [NSFileManager defaultManager];

  NSString *src = [[fm currentDirectoryPath] stringByAppendingPathComponent:@"santa-driver.kext"];
  NSString *dest = [NSTemporaryDirectory() stringByAppendingPathComponent:@"santa-driver.kext"];
  [fm removeItemAtPath:dest error:NULL]; // ensure dest is free
  if (![fm copyItemAtPath:src toPath:dest error:&error] || error) {
    TFAILINFO("Failed to copy kext: %s", error.description.UTF8String);
  }

  NSDictionary *attrs = @{
      NSFileOwnerAccountName : @"root",
      NSFileGroupOwnerAccountName : @"wheel",
      NSFilePosixPermissions : @0755
  };

  [fm setAttributes:attrs ofItemAtPath:dest error:NULL];
  for (NSString *path in [fm enumeratorAtPath:dest]) {
    [fm setAttributes:attrs ofItemAtPath:[dest stringByAppendingPathComponent:path] error:NULL];
  }

  NSURL *destURL = [NSURL fileURLWithPath:dest];
  OSStatus ret = KextManagerLoadKextWithURL((__bridge CFURLRef)destURL, NULL);
  if (ret != kOSReturnSuccess) {
    TFAILINFO("Failed to load kext: 0x%X", ret);
  }
  usleep(50000);
  TPASS();
}

- (void)runTests {
  printf("-> Connection tests:\n");

  // Test that connection can be established
  [self connectionTests];

  // Open driver and begin listening for events. Run this on background thread
  // so we can continue running tests.
  [self performSelectorInBackground:@selector(beginListening) withObject:nil];

  // Wait for driver to finish getting ready
  sleep(1);

  printf("\n-> Functional tests:\n");
  [self receiveAndBlockTests];
  [self receiveAndCacheTests];
  [self invalidatesCacheTests];
  [self invalidatesCacheAutoCloseTest];
  [self clearCacheTests];
  [self blocksDeniedTracedBinaries];
  [self testLargeBinary];
  [self testPendingTransitiveRules];
  [self testNoTransitiveRules];
  [self testFilemodPrefixFilter];

  printf("\n-> Performance tests:\n");
  [self testCachePerformance];

  printf("\nAll tests passed.\n\n");
}

@end

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    setbuf(stdout, NULL);

    if (getuid() != 0) {
      printf("Please run as root\n");
      exit(1);
    }

    chdir([[[NSBundle mainBundle] bundlePath] UTF8String]);

    SantaKernelTests *skt = [[SantaKernelTests alloc] init];
    printf("\nSanta Kernel Tests\n==================\n\n");
    printf("-> Loading tests:\n");
    [skt unloadDaemon];
    [skt unloadExtension];
    [skt loadExtension];
    printf("\n");

    [skt runTests];
    [skt unloadExtension];
  }
  return 0;
}
