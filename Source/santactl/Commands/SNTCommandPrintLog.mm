/// Copyright 2022 Google LLC
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

#import <Foundation/Foundation.h>
#include <google/protobuf/util/json_util.h>
#include <stdlib.h>

#include <iostream>
#include <string>

#include "Source/common/SNTLogging.h"
#include "Source/common/santa_proto_include_wrapper.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/binaryproto_proto_include_wrapper.h"
#include "google/protobuf/any.pb.h"

using google::protobuf::util::JsonPrintOptions;
using google::protobuf::util::MessageToJsonString;
// using santa::fsspool::binaryproto::LogBatch;
using santa::pb::v1::LogBatch;
namespace pbv1 = ::santa::pb::v1;

@interface SNTCommandPrintLog : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandPrintLog

REGISTER_COMMAND_NAME(@"printlog")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Prints the contents of Santa protobuf log files as JSON.";
}

+ (NSString *)longHelpText {
  return @"Prints the contents of serialized Santa protobuf logs as JSON.\n"
         @"Multiple paths can be provided. The output is a list of all the \n"
         @"SantaMessage entries per-file. E.g.: \n"
         @"  [\n"
         @"    [\n"
         @"      ... file 1 contents ...\n"
         @"    ],\n"
         @"    [\n"
         @"      ... file N contents ...\n"
         @"    ]\n"
         @"  ]";
}

- (void)runWithArguments:(NSArray *)arguments {
  JsonPrintOptions options;
  options.always_print_enums_as_ints = false;
  options.always_print_primitive_fields = true;
  options.preserve_proto_field_names = true;
  options.add_whitespace = true;

  for (int argIdx = 0; argIdx < [arguments count]; argIdx++) {
    NSString *path = arguments[argIdx];
    int fd = open([path UTF8String], O_RDONLY);
    if (fd == -1) {
      LOGE(@"Failed to open '%@': errno: %d: %s", path, errno, strerror(errno));
      continue;
    }

    LogBatch logBatch;
    bool ret = logBatch.ParseFromFileDescriptor(fd);
    close(fd);

    if (!ret) {
      LOGE(@"Failed to parse '%@'", path);
      continue;
    }

    std::string json;
    if (!MessageToJsonString(logBatch, &json, options).ok()) {
      LOGE(@"Unable to convert message to JSON in file: '%@'", path);
    }

    if (argIdx != 0) {
      std::cout << ",\n" << std::flush;
    } else {
      // Print the opening outer JSON array
      std::cout << "[";
    }

    std::cout << json;

    if (argIdx == ([arguments count] - 1)) {
      // Print the closing outer JSON array
      std::cout << "]\n";
    }
  }

  exit(EXIT_SUCCESS);
}

@end
