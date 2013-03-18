//
//   Kdb3.m
//   KeePass
//
//   Created by Qiang Yu on 11/22/09.
//   Copyright 2009 Qiang Yu. All rights reserved.
//

#import "Kdb3Reader.h"
#import "UUID.h"
#import "Utils.h"
#import "Kdb3Parser.h"
#import "AESDecryptSource.h"

#define READ_BYTES(X, Y, Z) (X = [[ByteBuffer alloc] initWithSize:Y dataSource:Z])

@interface Kdb3Reader (privateMethods)
-(id<InputDataSource>)createDecryptedInputDataSource:(id<InputDataSource>)source key:(ByteBuffer *)key;
-(void)readHeader:(id<InputDataSource>) source;
@end

@implementation Kdb3Reader
@synthesize _tree;
@synthesize major_ver, minor_ver;

+ (id<KdbReader>)reader
{
    id<KdbReader> reader = [[Kdb3Reader alloc] init];
    return reader;
}

#pragma mark -
#pragma mark private methods
- (void)readHeader:(id<InputDataSource>)input
{
	uint32_t flags, version;
	
	flags =   [Utils readInt32LE:input]; 
	version = [Utils readInt32LE:input];
	
    major_ver = (version & FILE_VERSION_CRITICAL_MASK) >> 16;
    minor_ver = (version & 0x0000FFFF);
    DLog(@"KDB 1 v%i.%02i",major_ver,minor_ver);
	if (major_ver > ((KDB3_VER & FILE_VERSION_CRITICAL_MASK) >> 16))
    {
		@throw [NSException exceptionWithName:@"Unsupported" reason:@"UnsupportedVersion" userInfo:nil];
	}	
		
    // TODO: TwoFish encription support
	if (!(flags & FLAG_RIJNDAEL))
		@throw [NSException exceptionWithName:@"Unsupported" reason:@"UnsupportedAlgorithm" userInfo:nil];	

	ByteBuffer *masterSeed = nil;
	READ_BYTES(masterSeed, 16, input);
	_password._masterSeed = masterSeed;
	[input readBytes:_encryptionIV length:16];
    
//    if (major_ver != 1)
    {
        _numGroups = [Utils readInt32LE:input];
        _numEntries = [Utils readInt32LE:input];
        
        //DLog(@"group# %d entry #%d", _numGroups, _numEntries);
        
        [input readBytes:_contentHash length:32];	

        ByteBuffer *transformSeed = nil;
        READ_BYTES(transformSeed, 32, input);	
        _password._transformSeed = transformSeed;
        
        _password._rounds = [Utils readInt32LE:input];
    }
}


- (id<InputDataSource>)createDecryptedInputDataSource:(id<InputDataSource>)source key:(ByteBuffer *)key
{
	AESDecryptSource *rv = [[AESDecryptSource alloc]initWithInputSource:source Keys:key._bytes andIV:_encryptionIV];
	return rv;
}

#pragma mark -
#pragma mark public methods
- (id<KdbTree>)load:(WrapperNSData *)input withPassword:(NSString *)password keyFile:(NSString *)keyFile
{
	_password = [[KdbPassword alloc] init];
	[self readHeader:input];
	ByteBuffer * finalKey = nil;
	id<InputDataSource> decrypted = nil;
	Kdb3Parser * parser;
	@try
    {
//		finalKey = [_password createFinalKey32ForPasssword:password coding:NSWindowsCP1252StringEncoding keyFile:keyFile kdbVersion:3];
		finalKey = [_password createFinalKey32ForPasssword:password coding:NSUTF8StringEncoding keyFile:keyFile kdbVersion:3];
		decrypted = [self createDecryptedInputDataSource:input key:finalKey];

//        _numGroups =  [Utils readInt32LE:input];
//        _numEntries = [Utils readInt32LE:input];
		
		parser = [[Kdb3Parser alloc] init];
		self._tree = [parser parse:decrypted numGroups:_numGroups numEntris:_numEntries];
	}
    @finally
    {
		parser = nil;
		finalKey = nil;
		decrypted = nil;
		_password = nil;
	}
	return self._tree;
}

-(id<KdbTree>)getKdbTree
{
	return self._tree;
}

@end
