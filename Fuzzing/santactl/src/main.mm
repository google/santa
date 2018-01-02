#include <iostream>
#include <cstdint>
#include <vector>

#include <SNTCommandSyncRuleDownload.h>
#include <SNTCommandSyncState.h>
#include <SNTCommandSyncConstants.h>
#include <SNTRule.h>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  NSData* buffer = [NSData dataWithBytes:static_cast<const void *>(data) length:size];
  if (buffer == nil) {
    return 0;
  }

  NSError *error;
  NSDictionary *response = [NSJSONSerialization JSONObjectWithData:buffer options:0 error:&error];
  if (response == nil) {
    return 0;
  }

  if (![response isKindOfClass:[NSDictionary class]]) {
    return 0;
  }

  if ([response objectForKey:kRules] == nil) {
    return 0;
  }

  SNTCommandSyncState *state = [[SNTCommandSyncState alloc] init];
  if (state == nil) {
    return 0;
  }

	SNTCommandSyncRuleDownload *obj = [[SNTCommandSyncRuleDownload alloc] initWithState:state];
  if (obj == nil) {
    return 0;
  }

  for (NSDictionary *ruleDict in response[kRules]) {
    SNTRule *rule = [obj ruleFromDictionary:ruleDict];
    if (rule != nil) {
      std::cerr << "Rule: " << [[rule description] UTF8String] << "\n";
    }
  }
 
  return 0;
}
