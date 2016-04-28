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

#import "SNTDERDecoder.h"

#import <Security/SecAsn1Coder.h>
#import <Security/SecAsn1Templates.h>

@interface SNTDERDecoder ()
@property NSDictionary *decodedObjects;
@end

@implementation SNTDERDecoder

#pragma mark Init

- (instancetype)initWithData:(NSData *)data {
  self = [super init];
  if (self) {
    if (!data) return nil;

    _decodedObjects = [self decodeData:data];
    if (!_decodedObjects || [_decodedObjects count] == 0) return nil;
  }
  return self;
}

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"/C=%@/O=%@/OU=%@/CN=%@",
                                    self.countryName,
                                    self.organizationName,
                                    self.organizationalUnit,
                                    self.commonName];
}

#pragma mark Accessors

- (NSString *)commonName {
  return self.decodedObjects[(__bridge id)kSecOIDCommonName];
}

- (NSString *)organizationName {
  return self.decodedObjects[(__bridge id)kSecOIDOrganizationName];
}

- (NSString *)organizationalUnit {
  return self.decodedObjects[(__bridge id)kSecOIDOrganizationalUnitName];
}

- (NSString *)countryName {
  return self.decodedObjects[(__bridge id)kSecOIDCountryName];
}

#pragma mark Private

/**
 * The DER data provided by NSURLProtectionSpace.distinguishedNames looks like
 * this:
 *
 * SEQUENCE {
 *   SET {
 *     SEQUENCE {
 *       OBJECT IDENTIFIER (2 5 4 6)
 *       PrintableString 'US'
 *     }
 *   }
 *   SET {
 *     SEQUENCE {
 *       OBJECT IDENTIFIER (2 5 4 10)
 *       PrintableString 'Megaco Inc'
 *     }
 *   }
 * }
 *
 * This method assumes the passed in data will be in that format. If it isn't,
 * the DER decoding will fail and this method will return nil.
 **/
- (NSDictionary *)decodeData:(NSData *)data {
  typedef struct {
    SecAsn1Oid oid;
    SecAsn1Item value;
  } OIDKeyValue;

  static const SecAsn1Template kOIDValueTemplate[] = {
      {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(OIDKeyValue)},
      {SEC_ASN1_OBJECT_ID, offsetof(OIDKeyValue, oid), NULL, 0},
      {SEC_ASN1_ANY_CONTENTS, offsetof(OIDKeyValue, value), NULL, 0},
      {0, 0, NULL, 0}};

  typedef struct {
    OIDKeyValue **vals;
  } OIDKeyValueList;

  static const SecAsn1Template kSetOfOIDValueTemplate[] = {
      {SEC_ASN1_SET_OF, 0, kOIDValueTemplate, sizeof(OIDKeyValueList)},
      {0, 0, NULL, 0}};

  typedef struct {
    OIDKeyValueList **lists;
  } OIDKeyValueListSeq;

  static const SecAsn1Template kSequenceOfSetOfOIDValueTemplate[] = {
      {SEC_ASN1_SEQUENCE_OF, 0, kSetOfOIDValueTemplate, sizeof(OIDKeyValueListSeq)},
      {0, 0, NULL, 0}};

  OSStatus err = errSecSuccess;
  SecAsn1CoderRef coder;

  err = SecAsn1CoderCreate(&coder);
  if (err != errSecSuccess) return nil;

  OIDKeyValueListSeq a;
  err = SecAsn1Decode(coder,
                      data.bytes,
                      data.length,
                      kSequenceOfSetOfOIDValueTemplate,
                      &a);
  if (err != errSecSuccess) {
    SecAsn1CoderRelease(coder);
    return nil;
  }

  // The data is decoded but now it's in a number of embedded structs.
  // Massage that into a nice dictionary of OID->String pairs.
  NSMutableDictionary *dict = [NSMutableDictionary dictionary];
  OIDKeyValueList *anAttr;
  for (NSUInteger i = 0; (anAttr = a.lists[i]); ++i) {
    OIDKeyValue *keyValue = anAttr->vals[0];

    // Sanity check
    if (keyValue->value.Length > data.length) {
      SecAsn1CoderRelease(coder);
      return nil;
    }

    // Get the string value. First try creating as a UTF-8 string. If that fails,
    // fallback to trying as an ASCII string. If it still doesn't work, continue on
    // to the next value.
    NSString *valueString;
    valueString = [[NSString alloc] initWithBytes:keyValue->value.Data
                                           length:keyValue->value.Length
                                         encoding:NSUTF8StringEncoding];
    if (!valueString) {
      valueString = [[NSString alloc] initWithBytes:keyValue->value.Data
                                             length:keyValue->value.Length
                                           encoding:NSASCIIStringEncoding];
    }
    if (!valueString) continue;

    // The OID is still encoded, so we need to decode it.
    NSString *objectId = [SNTDERDecoder decodeOIDWithBytes:keyValue->oid.Data
                                                    length:keyValue->oid.Length];

    // Add to the dictionary
    dict[objectId] = valueString;
  }

  SecAsn1CoderRelease(coder);
  return dict;
}

/**
 * Decodes an ASN.1 Object Identifier into a string separated by periods.
 * See http://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx for
 * details of the encoding.
 **/
+ (NSString *)decodeOIDWithBytes:(unsigned char *)bytes length:(NSUInteger)length {
  NSMutableArray *objectId = [NSMutableArray array];
  BOOL inVariableLengthByte = NO;
  NSUInteger variableLength = 0;
  for (NSUInteger i = 0; i < length; ++i) {
    if (i == 0) {
      // The first byte is actually two values, the top 4 bits are the first value * 40
      // and the bottom 4 bits are the second value.
      [objectId addObject:@((NSUInteger)bytes[i] / 40)];
      [objectId addObject:@((NSUInteger)bytes[i] % 40)];
    } else {
      // The remaining bytes are encoded with Variable Length Quantity.
      unsigned char byte = bytes[i];
      if (byte & 0x80) {
        inVariableLengthByte = YES;

        NSUInteger a = (NSUInteger)(byte & ~0x80);
        variableLength = variableLength << 7;
        variableLength += a;
      } else if (inVariableLengthByte) {
        NSUInteger a = (NSUInteger)(byte & ~0x80);
        variableLength = variableLength << 7;
        variableLength += a;
        inVariableLengthByte = NO;
        [objectId addObject:@(variableLength)];
        variableLength = 0;
      } else {
        [objectId addObject:@((NSUInteger)byte)];
      }
    }
  }
  return [objectId componentsJoinedByString:@"."];
}

@end
