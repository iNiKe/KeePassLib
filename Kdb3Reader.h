//
//   Kdb3.h
//   KeePass
//
//   Created by Qiang Yu on 11/22/09.
//   Copyright 2009 Qiang Yu. All rights reserved.
//

/**
 * KDB3 Support
 */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#import "Kdb.h"
#import "Kdb3Node.h"
#import "KdbReader.h"
#import "WrapperNSData.h"
#import "KdbPassword.h"

/**
 * Read a kdb3 file into a memory tree
 */
@interface Kdb3Reader:NSObject<KdbReader>{
	uint32_t _numGroups, _numEntries;
	uint8_t _contentHash[32];
	uint8_t _encryptionIV[16];	
	KdbPassword * _password;
	id<KdbTree> _tree;
}

@property (nonatomic, strong) id<KdbTree> _tree;
@property (nonatomic, readonly) uint8_t major_ver, minor_ver;

- (id<KdbTree>)load:(WrapperNSData *)input withPassword:(NSString *)password keyFile:(NSString *)keyFile;
+ (id<KdbReader>)reader;

@end



