//
//  Kdb3Persist.h
//  KeePass2
//
//  Created by Qiang Yu on 2/16/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AESEncryptSource.h"
#import "KdbPassword.h"
#import "Kdb.h"

/**
 Given a KDB3 Tree, Kdb3Writer persist it to hard driver
 */
@interface Kdb3Writer : NSObject
{
	uint8_t _header[KDB3_HEADER_SIZE];
	uint8_t _encryptionIV[16];	
	KdbPassword * _password;	
}
- (void)persist:(id<KdbTree>)tree file:(NSString *)fileName withPassword:(NSString *)password keyFile:(NSString *)keyFile;
- (void)newFile:(NSString *)fileName withPassword:(NSString *)password keyFile:(NSString *)keyFile;

@end
