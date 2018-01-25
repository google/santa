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

@import Foundation;
@import IOKit;

#import <CommonCrypto/CommonDigest.h>

#include <cmath>
#include <ctime>
#include <iostream>
#include <mach/mach.h>
#include <numeric>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <vector>

#include "SNTKernelCommon.h"

///
/// Kernel Extension Tests
///
/// Build and launch as root while the kernel extension is loaded and nothing is already connected.
///

#define TSTART(testName) \
    do { printf("   %-50s ", testName); } while (0)
#define TPASS() \
    do { printf("\x1b[32mPASS\x1b[0m\n"); } while (0)
#define TPASSINFO(fmt, ...) \
    do { printf("\x1b[32mPASS\x1b[0m\n      " fmt "\n", ##__VA_ARGS__); } while (0)
#define TFAIL() \
    do { \
      printf("\x1b[31mFAIL\x1b[0m\n"); \
      exit(1); \
    } while (0)
#define TFAILINFO(fmt, ...) \
    do { \
      printf("\x1b[31mFAIL\x1b[0m\n   -> " fmt "\n\nTest failed.\n\n", ##__VA_ARGS__); \
      exit(1); \
    } while (0)

@interface SantaKernelTests : NSObject
@property io_connect_t connection;
@property int timesSeenLs;
@property int timesSeenCat;
@property int timesSeenCp;

@property int testExeIteration;
@property int timesSeenTestExeIteration;
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

#pragma mark - Driver Helpers

/// Call in-kernel function: |kSantaUserClientAllowBinary| or |kSantaUserClientDenyBinary|
/// passing the |vnodeID|.
- (void)postToKernelAction:(santa_action_t)action forVnodeID:(uint64_t)vnodeid {
  if (action == ACTION_RESPOND_ALLOW) {
    IOConnectCallScalarMethod(self.connection, kSantaUserClientAllowBinary, &vnodeid, 1, 0, 0);
  } else if (action == ACTION_RESPOND_DENY) {
    IOConnectCallScalarMethod(self.connection, kSantaUserClientDenyBinary, &vnodeid, 1, 0, 0);
  } else if (action == ACTION_RESPOND_ACK) {
    IOConnectCallScalarMethod(self.connection, kSantaUserClientAcknowledgeBinary,
                              &vnodeid, 1, 0, 0);
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
  kern_return_t kr;
  santa_message_t vdata;
  UInt32 dataSize;
  IODataQueueMemory *queueMemory;
  mach_port_t receivePort;

  mach_vm_address_t address = 0;
  mach_vm_size_t size = 0;

  TSTART("Allocates a notification port");
  if (!(receivePort = IODataQueueAllocateNotificationPort())) {
    TFAIL();
  }
  TPASS();

  TSTART("Registers the notification port");
  kr = IOConnectSetNotificationPort(self.connection, QUEUETYPE_DECISION, receivePort, 0);
  if (kr != kIOReturnSuccess) {
    mach_port_destroy(mach_task_self(), receivePort);
    TFAILINFO("KR: %d", kr);
    return;
  }
  TPASS();

  TSTART("Maps shared memory");
  kr = IOConnectMapMemory(self.connection, QUEUETYPE_DECISION, mach_task_self(),
                          &address, &size, kIOMapAnywhere);
  if (kr != kIOReturnSuccess) {
    mach_port_destroy(mach_task_self(), receivePort);
    TFAILINFO("KR: %d", kr);
  }
  TPASS();

  // Fetch the SHA-256 of /bin/ed, as we'll be using that for the cache invalidation test.
  NSString *edSHA = [self sha256ForPath:@"/bin/ed"];

  // Create the RE used for matching testexe's
  NSString *cwd = [[NSFileManager defaultManager] currentDirectoryPath];
  NSString *pattern = [cwd stringByAppendingPathComponent:@"testexe\\.(\\d+)"];
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];

  /// Begin listening for events
  queueMemory = (IODataQueueMemory *)address;
  do {
    while (IODataQueueDataAvailable(queueMemory)) {
      dataSize = sizeof(vdata);
      kr = IODataQueueDequeue(queueMemory, &vdata, &dataSize);
      if (kr == kIOReturnSuccess) {
        if (vdata.action != ACTION_REQUEST_BINARY) continue;

        if ([[self sha256ForPath:@(vdata.path)] isEqual:edSHA]) {
          [self postToKernelAction:ACTION_RESPOND_DENY forVnodeID:vdata.vnode_id];
        } else if (strncmp("/bin/mv", vdata.path, strlen("/bin/mv")) == 0) {
          [self postToKernelAction:ACTION_RESPOND_DENY forVnodeID:vdata.vnode_id];
        } else if (strncmp("/bin/ls", vdata.path, strlen("/bin/ls")) == 0) {
          [self postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:vdata.vnode_id];
          self.timesSeenLs++;
        } else if (strncmp("/bin/cp", vdata.path, strlen("/bin/cp")) == 0) {
          [self postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:vdata.vnode_id];
          self.timesSeenCp++;
        } else if (strncmp("/bin/cat", vdata.path, strlen("/bin/cat")) == 0) {
          [self postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:vdata.vnode_id];
          self.timesSeenCat++;
        } else if (strncmp("/usr/bin/cal", vdata.path, strlen("/usr/bin/cal")) == 0) {
          static int count = 0;
          if (count++) TFAILINFO("Large binary should not re-request");
          [self postToKernelAction:ACTION_RESPOND_ACK forVnodeID:vdata.vnode_id];
          for (int i = 0; i < 15; ++i) {
            printf("\033[s");  // save cursor position
            printf("%i/15", i);
            sleep(1);
            printf("\033[u");  // restore cursor position
          }
          printf("\033[K\033[u");  // clear line, restore cursor position
          [self postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:vdata.vnode_id];
        } else if (strncmp("/bin/ln", vdata.path, strlen("/bin/ln")) == 0) {
          [self postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:vdata.vnode_id];

          TSTART("Sends valid pid/ppid");
          if (vdata.pid < 1 || vdata.ppid < 1) {
            TFAIL();
          }
          TPASSINFO("Received pid, ppid: %d, %d", vdata.pid, vdata.ppid);
        } else {
          NSString *path = @(vdata.path);

          // If current executable is one of our test exe's from handlesLotsOfBinaries,
          // check that the number has increased.
          NSArray *matches = [re matchesInString:path
                                         options:0
                                           range:NSMakeRange(0, path.length)];
          if (matches.count == 1 && [matches[0] numberOfRanges] == 2) {
            NSUInteger count = [[path substringWithRange:[matches[0] rangeAtIndex:1]] intValue];
            if (count <= self.testExeIteration && count > 0) {
              self.timesSeenTestExeIteration++;
              if (self.timesSeenTestExeIteration > 2) {
                TFAILINFO("Saw same binary several times");
              }
            } else {
              self.timesSeenTestExeIteration = 0;
              self.testExeIteration = (int)count;
            }
          }

          // Allow everything not related to our testing.
          [self postToKernelAction:ACTION_RESPOND_ALLOW forVnodeID:vdata.vnode_id];
        }
      } else {
        TFAILINFO("Error receiving data: %d", kr);
      }
    }
  } while (IODataQueueWaitForAvailableData(queueMemory, receivePort) == kIOReturnSuccess);

  IOConnectUnmapMemory(self.connection, kIODefaultMemoryType, mach_task_self(), address);
  mach_port_destroy(mach_task_self(), receivePort);
}

#pragma mark - Functional Tests

/// Tests that blocking works correctly
- (void)receiveAndBlockTests {
  TSTART("Blocks denied binaries");

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

/// Tests that an allowed binary is cached
- (void)receiveAndCacheTests {
  TSTART("Permits & caches allowed binaries");

  self.timesSeenLs = 0;

  NSTask *ls = [self taskWithPath:@"/bin/ls"];
  [ls launch];
  [ls waitUntilExit];

  if (self.timesSeenLs != 1) {
    TFAILINFO("Didn't record first run of ls");
  }

  ls = [self taskWithPath:@"/bin/ls"];
  [ls launch];
  [ls waitUntilExit];

  if (self.timesSeenLs > 1) {
    TFAILINFO("Received request for ls a second time");
  }

  TPASS();
}

/// Tests that a write to a cached vnode will invalidate the cached response for that file
- (void)invalidatesCacheTests {
  TSTART("Invalidates cache for manually closed FDs");

  // Copy the ls binary to a new file
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm copyItemAtPath:@"/bin/pwd" toPath:@"invalidacachetest_tmp" error:nil]) {
    TFAILINFO("Failed to create temp file");
  }

  // Launch the new file to put it in the cache
  NSTask *pwd = [self taskWithPath:@"invalidacachetest_tmp"];
  [pwd launch];
  [pwd waitUntilExit];

  // Exit if this fails with a useful message.
  if ([pwd terminationStatus] != 0) {
    TFAILINFO("First launch of test binary failed");
  }

  // Now replace the contents of the test file (which is cached) with the contents of /bin/ed,
  // which is 'blacklisted' by SHA-256 during the tests.
  FILE *infile = fopen("/bin/ed", "r");
  FILE *outfile = fopen("invalidacachetest_tmp", "w");
  int ch;
  while ((ch = fgetc(infile)) != EOF) {
    fputc(ch, outfile);
  }
  fclose(infile);

  // Now try running the temp file again. If it succeeds, the test failed.
  NSTask *ed = [self taskWithPath:@"invalidacachetest_tmp"];

  @try {
    [ed launch];
    [ed waitUntilExit];
    TFAILINFO("Launched after write while file open");
    [fm removeItemAtPath:@"invalidacachetest_tmp" error:nil];
  } @catch (NSException *exception) {
    // This is a pass, but we have more to do.
  }

  // Close the file to flush the write.
  fclose(outfile);

  // And try running the temp file again. If it succeeds, the test failed.
  ed = [self taskWithPath:@"invalidacachetest_tmp"];

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

- (void)invalidatesCacheAutoCloseTest {
  TSTART("Invalidates cache for auto-closed FDs");

  // Check invalidations when kernel auto-closes descriptors
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm copyItemAtPath:@"/bin/pwd" toPath:@"invalidacachetest_tmp" error:nil]) {
    TFAILINFO("Failed to create temp file");
  }

  // Launch the new file to put it in the cache
  NSTask *pwd = [self taskWithPath:@"invalidacachetest_tmp"];
  [pwd launch];
  [pwd waitUntilExit];

  // Exit if this fails with a useful message.
  if ([pwd terminationStatus] != 0) {
    TFAILINFO("Second launch of test binary failed");
  }

  // Replace file contents
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

/// Tests the clear cache function works correctly
- (void)clearCacheTests {
  TSTART("Can clear cache");

  self.timesSeenCat = 0;

  NSTask *cat = [self taskWithPath:@"/bin/cat"];
  [cat launch];
  [cat waitUntilExit];

  if (self.timesSeenCat != 1) {
    TFAILINFO("Didn't record first run of cat");
  }

  [self flushCache];

  cat = [self taskWithPath:@"/bin/cat"];
  [cat launch];
  [cat waitUntilExit];

  if (self.timesSeenCat != 2) {
    TFAIL();
  }

  TPASS();
}

/// Tests that the kernel still denies blocked binaries even if launched while traced
- (void)blocksDeniedTracedBinaries {
  TSTART("Denies blocked processes running while traced");

  pid_t pid = fork();
  if (pid < 0) {
    TFAILINFO("Failed to fork");
  } else if (pid > 0) {
    int status;
    waitpid(pid, &status, 0);
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

/// Tests that the kernel can handle _lots_ of executions.
- (void)handlesLotsOfBinaries {
  TSTART("Handles lots of binaries");

  const int LIMIT = 12000;

  for (int i = 0; i < LIMIT; ++i) {
    printf("\033[s");  // save cursor position

    printf("%d/%i", i + 1, LIMIT);

    NSString *fname = [@"testexe" stringByAppendingFormat:@".%i", i];
    [[NSFileManager defaultManager] copyItemAtPath:@"/bin/hostname" toPath:fname error:NULL];

    @try {
      NSTask *testexec = [self taskWithPath:fname];
      [testexec launch];
      [testexec waitUntilExit];
    } @catch (NSException *e) {
      TFAILINFO("Failed to launch");
    }

    unlink([fname UTF8String]);
    printf("\033[u");  // restore cursor position
  }
  printf("\033[K\033[u");  // clear line, restore cursor position

  TPASS();
}

- (void)testCachePerformance {
  TSTART("Test cache performance");

  // Execute echo 100 times, saving the time taken for each run
  std::vector<double> times;
  for (int i = 0; i < 100; ++i) {
    printf("\033[s");  // save cursor position
    printf("%d/%d", i + 1, 100);
    NSTask *t = [[NSTask alloc] init];
    t.launchPath = @"/bin/echo";
    t.standardOutput = [NSPipe pipe];
    auto start = std::chrono::steady_clock::now();
    [t launch];
    [t waitUntilExit];
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (i > 5) times.push_back(duration);
    printf("\033[u");  // restore cursor position
  }

  printf("\033[K\033[u");  // clear line, restore cursor position

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
  TSTART("Handles large binary");

  @try {
    NSTask *testexec = [self taskWithPath:@"/usr/bin/cal"];
    [testexec launch];
    [testexec waitUntilExit];
  } @catch (NSException *e) {
    TFAILINFO("Failed to launch");
  }

  TPASS();
}

#pragma mark - Main

- (void)runTests {
  printf("\nSanta Kernel Tests\n==================\n");
  printf("-> Connection tests:\n");

  // Test that connection can be established
  [self connectionTests];

  // Open driver and begin listening for events. Run this on background thread
  // so we can continue running tests.
  [self performSelectorInBackground:@selector(beginListening) withObject:nil];

  // Wait for driver to finish getting ready
  sleep(1);
  printf("\n-> Functional tests:\033[m\n");

  [self receiveAndBlockTests];
  [self receiveAndCacheTests];
  [self invalidatesCacheTests];
  [self invalidatesCacheAutoCloseTest];
  [self clearCacheTests];
  [self blocksDeniedTracedBinaries];

  printf("\n-> Performance tests:\033[m\n");
  [self testCachePerformance];
  [self testLargeBinary];
  [self handlesLotsOfBinaries];

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

    SantaKernelTests *skt = [[SantaKernelTests alloc] init];
    [skt runTests];
  }
  return 0;
}
