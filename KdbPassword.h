//
//  Password.h
//  KeePass2
//
//  Created by Qiang Yu on 1/5/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ByteBuffer.h"

@interface KdbPassword : NSObject<NSXMLParserDelegate>
{
	ByteBuffer *_masterSeed;
	ByteBuffer *_transformSeed;	
	uint64_t _rounds;	
    BOOL _isKeyfile, _isKey, _hasError;
    NSMutableArray *_elements;
    NSMutableData *_keyData;
}

@property(nonatomic, strong) ByteBuffer *_masterSeed;
@property(nonatomic, strong) ByteBuffer *_transformSeed;
@property(nonatomic, assign) uint64_t _rounds;
@property (nonatomic, readonly) BOOL finished;

- (ByteBuffer *)createFinalKey32ForPasssword:(NSString *)password coding:(NSStringEncoding)coding keyFile:(NSString *)keyFile kdbVersion:(uint8_t)ver;

@end
