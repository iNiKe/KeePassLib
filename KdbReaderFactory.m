//
//  KdbReaderFactory.m
//  KeePass2
//
//  Created by Qiang Yu on 3/8/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import "KdbReaderFactory.h"
#import "Kdb3Reader.h"
#import "Kdb4Reader.h"
#import "Utils.h"

@implementation KdbReaderFactory

/*
 * This function checks the signature of the input stream, and returns
 * appropriate KdbReader instance;
 * The caller is the owner of the reader returned, and should release it after use;
 * This function returns nil if the signatures are unknown
 *
 * The way to use this class and KDB reader is:
   id<KdbReader> read = [KdbReaderFactory kdbReader:input];
   [read load:input withPassword:password];
   [read release];
 */
+ (id<KdbReader>)kdbReader:(WrapperNSData *)input
{
	uint32_t signature1 = [Utils readInt32LE:input];
	uint32_t signature2 = [Utils readInt32LE:input];
	
    id<KdbReader> reader = nil;
    if (signature1 == KEEPASS_SIG)
    {
        if (signature2 == KDB3_SIG2)
        {
            reader = [Kdb3Reader reader];
        }
        else if (signature2 == KDB4_SIG2 || signature2 == KDB4_PRE_SIG2)
        {
            reader = [Kdb4Reader reader];
        }
    }
    
    if (!reader)
    {
        @throw [NSException exceptionWithName:@"Unsupported" reason:@"UnsupportedVersion" userInfo:nil];
    }
    return reader;
}

@end
