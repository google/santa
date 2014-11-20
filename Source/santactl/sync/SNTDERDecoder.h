/// This is a simple ASN.1 decoder that utilizes Apple's SecAsn1Decode
/// to parse the @c distinguishedNames property of NSURLProtectionSpace.
@interface SNTDERDecoder : NSObject

@property(readonly) NSString *commonName;
@property(readonly) NSString *organizationName;
@property(readonly) NSString *organizationalUnit;
@property(readonly) NSString *countryName;

/// Designated initializer. Pass in one of the NSData objects in the
/// NSURLProtectionSpace.distinguishedNames array
/// Returns nil if decoding fails to find any expected objects
- (instancetype)initWithData:(NSData *)data;

@end
