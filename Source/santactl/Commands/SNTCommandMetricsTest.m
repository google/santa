/// Copyright 2021 Google Inc. All rights reserved.
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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/santactl/Commands/SNTCommandMetrics.h"
#import "Source/santametricservice/Formats/SNTMetricFormatTestHelper.h"

@interface SNTCommandMetricsTest : XCTestCase
@property NSString *tempDir;
@property id mockConfigurator;
@end

@implementation SNTCommandMetricsTest

- (void)setUp {
  // create a temp dir
  char template[] = "/tmp/sntcommandmetrictest.XXXXXXX";
  char *tempPath = mkdtemp(template);

  if (tempPath == NULL) {
    NSLog(@"Unable to make temp directory");
    exit(1);
  }

  self.tempDir =
    [[NSFileManager defaultManager] stringWithFileSystemRepresentation:tempPath
                                                                length:strlen(tempPath)];
  // mock the SNTConfigurator
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator exportMetrics]).andReturn(YES);
  OCMStub([self.mockConfigurator metricFormat]).andReturn(SNTMetricFormatTypeMonarchJSON);
  OCMStub([self.mockConfigurator metricURL])
    .andReturn([NSURL URLWithString:@"http://localhost:2444/submit"]);
  OCMStub([self.mockConfigurator metricExportInterval]).andReturn((NSUInteger)30);
}

- (void)tearDown {
  // delete the temp dir
  NSError *err;
  [[NSFileManager defaultManager] removeItemAtPath:self.tempDir error:&err];

  if (err != nil) {
    NSLog(@"unable to remove %@, error: %@", self.tempDir, err);
  }

  dup2(1, STDOUT_FILENO);
}

- (void)testPrettyPrintingJSON {
  NSError *err;
  NSString *path = [[NSBundle bundleForClass:[self class]] resourcePath];
  path = [path stringByAppendingPathComponent:@"Commands/testdata/metrics-prettyprint.json"];

  NSString *goldenFileContents = [[NSString alloc]
    initWithData:[NSData dataWithContentsOfFile:path options:NSDataReadingUncached error:&err]
        encoding:NSUTF8StringEncoding];

  XCTAssertNil(err, @"failed to read golden file %@ for testPrettyPrintingJSON", path);

  SNTCommandMetrics *metricsCmd = [[SNTCommandMetrics alloc] init];

  NSString *outputPath = [NSString pathWithComponents:@[ self.tempDir, @"test.data" ]];

  // redirect stdout
  int fd = open([outputPath UTF8String], O_TRUNC | O_WRONLY | O_CREAT, 0600);
  int saved_stdout = dup(fileno(stdout));
  dup2(fd, fileno(stdout));

  [metricsCmd prettyPrintMetrics:[SNTMetricFormatTestHelper createValidMetricsDictionary]
                          asJSON:YES];

  // restore stdout
  fflush(stdout);
  dup2(saved_stdout, fileno(stdout));

  // open test file assert equal with golden file
  NSString *commandOutput =
    [[NSString alloc] initWithData:[NSData dataWithContentsOfFile:outputPath]
                          encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(goldenFileContents, commandOutput,
                        @"Metrics command command did not produce expected output");
}

- (void)testPrettyPrinting {
  NSError *err;
  NSString *path = [[NSBundle bundleForClass:[self class]] resourcePath];
  path = [path stringByAppendingPathComponent:@"Commands/testdata/metrics-prettyprint.txt"];

  NSString *goldenFileContents = [[NSString alloc]
    initWithData:[NSData dataWithContentsOfFile:path options:NSDataReadingUncached error:&err]
        encoding:NSUTF8StringEncoding];

  XCTAssertNil(err, @"failed to read golden file %@ for testPrettyPrinting", path);

  SNTCommandMetrics *metricsCmd = [[SNTCommandMetrics alloc] init];

  NSString *outputPath = [NSString pathWithComponents:@[ self.tempDir, @"test.data" ]];

  // redirect stdout
  int fd = open([outputPath UTF8String], O_TRUNC | O_WRONLY | O_CREAT, 0600);
  int saved_stdout = dup(fileno(stdout));
  dup2(fd, fileno(stdout));

  [metricsCmd prettyPrintMetrics:[SNTMetricFormatTestHelper createValidMetricsDictionary]
                          asJSON:NO];

  // restore stdout
  fflush(stdout);
  dup2(saved_stdout, fileno(stdout));

  // open test file assert equal with golden file
  NSString *commandOutput =
    [[NSString alloc] initWithData:[NSData dataWithContentsOfFile:outputPath]
                          encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(goldenFileContents, commandOutput,
                        @"Metrics command command did not produce expected output");
}

@end
