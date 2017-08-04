//
//  SNTCommand.m
//  Santa
//
//  Created by Phillip Nguyen on 8/4/17.
//
//

#import "SNTCommand.h"

@implementation SNTCommand

+ (BOOL)requiresRoot { return NO; }
+ (BOOL)requiresDaemonConn { return NO; }
+ (NSString *)shortHelpText { return @""; }
+ (NSString *)longHelpText { return @""; }

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  id cmd = [[self alloc] initWithDaemonConnection:daemonConn];
  [cmd runWithArguments:arguments];
}

- (instancetype)initWithDaemonConnection:(SNTXPCConnection *)daemonConn {
  self = [super init];
  if (!self) return nil;
  _daemonConn = daemonConn;
  return self;
}

- (void)runWithArguments:(NSArray *)arguments {
  // print error message
}

- (void)printErrorUsageAndExit:(NSString *)error {
  printf("%s\n\n", [error UTF8String]);
  printf("%s\n", [[[self class] longHelpText] UTF8String]);
  exit(1);
}

@end
