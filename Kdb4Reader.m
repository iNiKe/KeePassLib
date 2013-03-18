//
//  Kdb4.m
//  KeePass2
//
//  Created by Qiang Yu on 1/3/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import "Kdb4Reader.h"
#import "Kdb.h"
#import "HashedInputData.h"
#import "GZipInputData.h"
#import "Kdb4Parser.h"
#import "Utils.h"
#import "AESDecryptSource.h"
#import "Arc4RandomStream.h"
#import "Salsa20RandomStream.h"

@interface Kdb4Reader (PrivateMethods)
- (void)readHeader:(id<InputDataSource>)source;
- (id<InputDataSource>)createDecryptedInputDataSource:(id<InputDataSource>)source key:(ByteBuffer *)key;
@end


@implementation Kdb4Reader
@synthesize _tree;
@synthesize fileVersion = _fileVersion;
@synthesize headerComment = _headerComment;
@synthesize password = _password;

+ (id<KdbReader>)reader
{
    id<KdbReader> reader = [[Kdb4Reader alloc] init];
    return reader;
}

- (id)init
{
	if ((self = [super init]))
    {
		_password = [[KdbPassword alloc] init];
        _randomStreamID = CSR_ARC4VARIANT; // KeePass 2.00 alpha default
	}
	return self;
}


#pragma mark -
#pragma mark Public Methods

//TODO:
// only Kdb4Format.Default is supported; will add support for Kdb4Format.PlainXml
//
- (id<KdbTree>)load:(WrapperNSData *)source withPassword:(NSString *)password keyFile:(NSString *)keyFile
{
	ByteBuffer * finalKey = nil;
	
	id<InputDataSource> decrypted = nil;
	id<InputDataSource> hashed = nil;
	id<InputDataSource> readerStream = nil;
	
	@try
    {
		//read header
		[self readHeader:source];
		
		//decrypt data
		finalKey = [_password createFinalKey32ForPasssword:password coding:NSUTF8StringEncoding keyFile:keyFile kdbVersion:4];
		decrypted = [self createDecryptedInputDataSource:source key:finalKey];
				
        if (_streamStartBytes)
        {
            //double check start block
            ByteBuffer *startBytes = [[ByteBuffer alloc] initWithSize:32];
            [decrypted readBytes:startBytes._bytes length:32];
            if (![startBytes isEqual:_streamStartBytes])
            {
                @throw [NSException exceptionWithName:@"DecryptError" reason:@"DecryptError" userInfo:nil];
            }
            hashed = [[HashedInputData alloc] initWithDataSource:decrypted];
        }
        else
            hashed = decrypted;
        // TODO: What version started using hashed stream?
		
		id<InputDataSource> readerStream = nil;
		
		if (_compressionAlgorithm == COMPRESSION_GZIP)
        {
			readerStream = [[GZipInputData alloc] initWithDataSource:hashed];
		}
        else
        {
			readerStream = hashed;
		}
		
		//should PlainXML supported?
		id<RandomStream> rs = nil;
		if(_randomStreamID == CSR_SALSA20)
        {
			rs = [[Salsa20RandomStream alloc] init:_protectedStreamKey._bytes len:_protectedStreamKey._size];
		}
        else if (_randomStreamID == CSR_ARC4VARIANT)
        {
			rs = [[Arc4RandomStream alloc] init:_protectedStreamKey._bytes len:_protectedStreamKey._size];
		}
        else
        {
			@throw [NSException exceptionWithName:@"Unsupported" reason:@"UnsupportedRandomStreamID" userInfo:nil];
		}
		
		Kdb4Parser *parser = [[Kdb4Parser alloc] init];
		parser._randomStream = rs;
		
		self._tree = (Kdb4Tree *)[parser parse:readerStream];
        DLog(@"Groups: %i Entries: %i", parser.groupsCount, parser.entriesCount);
	}
	@finally
    {
		hashed = nil;
		decrypted = nil;
		readerStream = nil;
		
		finalKey = nil;
		source = nil;		 
	}
	
	return self._tree;
}

- (id<KdbTree>)getKdbTree
{
	return self._tree;
}


#pragma mark -
#pragma mark Private Methods
/*
 * Decrypt remaining bytes
 */
- (id<InputDataSource>)createDecryptedInputDataSource:(id<InputDataSource>)source key:(ByteBuffer *)key
{
	AESDecryptSource * rv = [[AESDecryptSource alloc] initWithInputSource:source Keys:key._bytes andIV:_encryptionIV._bytes];
	return rv;	
}

- (void)readHeader:(id<InputDataSource>)source
{
    [self readHeader:source stop:YES];
}

- (NSException *)readHeader:(id<InputDataSource>)source stop:(BOOL)stop
{
    NSException *exception = nil;
    _cipherUUID = nil; _password._masterSeed = nil; _password._transformSeed = nil;
    _encryptionIV = nil; _protectedStreamKey = nil; _streamStartBytes = nil; _fileVersion = 0;
	_fileVersion = [Utils readInt32LE:source];
//	DLog(@"VERSION:%X", _fileVersion);
		
	if ( ((_fileVersion & FILE_VERSION_CRITICAL_MASK) > (KDB4_VER & FILE_VERSION_CRITICAL_MASK)) )
    {
		exception = [NSException exceptionWithName:@"Unsupported" reason:@"UnsupportedVersion" userInfo:nil];
	}	
	
	BOOL eoh = NO; //end of header
	
    if (!exception)
	while (!eoh)
    {
		uint8_t  fieldType = [Utils readInt8LE:source];
		uint16_t fieldSize = [Utils readInt16LE:source];
		switch (fieldType)
        {
			case HEADER_COMMENT:
            {
				ByteBuffer *comment;
				READ_BYTES(comment, fieldSize, source);
//				DLog(@"HEADER_COMMENT:%@", comment);
				break;
			}
			case HEADER_EOH:
            {
				ByteBuffer * header;
				READ_BYTES(header, fieldSize, source);
//				DLog(@"HEADER_EOH:%@", header);
				eoh = YES;
				break;
			}
			case HEADER_CIPHERID:
            {
				if (fieldSize != 16)
                {
					exception = [NSException exceptionWithName:@"InvalidHeader" reason:@"InvalidCipherId" userInfo:nil];
                    break;
                }
				_cipherUUID = [[UUID alloc] initWithSize:16 dataSource:source];
//				DLog(@"HEADER_CIPHERID:%@", _cipherUUID);				
				if (![_cipherUUID isEqual:[UUID getAESUUID]])
                {
					exception = [NSException exceptionWithName:@"Unsupported" reason:@"UnsupportedCipher" userInfo:nil];
				}
				break;
			}
			case HEADER_MASTERSEED:
            {
				if (fieldSize != 32)
                {
					exception = [NSException exceptionWithName:@"InvalidHeader" reason:@"InvalidMasterSeed" userInfo:nil];
                    break;
                }
				ByteBuffer *masterSeed;
				READ_BYTES(masterSeed, fieldSize, source);
				_password._masterSeed = masterSeed;
//				DLog(@"HEADER_MASTERSEED:%@", masterSeed);	
				break;
			}
			case HEADER_TRANSFORMSEED:
            {
				if (fieldSize != 32)
                {
					exception = [NSException exceptionWithName:@"InvalidHeader" reason:@"InvalidTransformSeed" userInfo:nil];
                    break;
                }
				ByteBuffer *transformSeed;
				READ_BYTES(transformSeed, fieldSize, source);
				_password._transformSeed = transformSeed;
//				DLog(@"HEADER_TRANSFORMSEED:%@", transformSeed);
				break;
			}
			case HEADER_ENCRYPTIONIV:
            {
				READ_BYTES(_encryptionIV, fieldSize, source);
				//DLog(@"HEADER_ENCRYPTIONIV:%@", _encryptionIV);
				break;
			}
			case HEADER_PROTECTEDKEY:
            {
				READ_BYTES(_protectedStreamKey, fieldSize, source);
//				DLog(@"HEADER_PROTECTEDKEY:%@", _protectedStreamKey);
				break;
			}
			case HEADER_STARTBYTES:
            {
				READ_BYTES(_streamStartBytes, fieldSize, source);
//				DLog(@"HEADER_STARTBYTES:%@", _streamStartBytes);
				break;
			}
			case HEADER_TRANSFORMROUNDS:
            {
				_password._rounds = [Utils readInt64LE:source];
//				DLog(@"HEADER_TRANSFORMROUNDS:%qX", _password._rounds);
				break;
			}
			case HEADER_COMPRESSION:
            {
				_compressionAlgorithm = [Utils readInt32LE:source];
				if (_compressionAlgorithm >= COMPRESSION_COUNT)
                {
					exception = [NSException exceptionWithName:@"InvalidHeader" reason:@"InvalidCompression" userInfo:nil];
                }
//				DLog(@"HEADER_COMPRESSION:%X", _compressionAlgorithm);
				break;
			}
			case HEADER_RANDOMSTREAMID:
            {
				_randomStreamID = [Utils readInt32LE:source];
				if (_randomStreamID >= CSR_COUNT)
                {
					exception = [NSException exceptionWithName:@"InvalidHeader" reason:@"InvalidCSRAlgorithm" userInfo:nil];
                }
//				DLog(@"HEADER_RANDOMSTREAMID:%X", _randomStreamID);
				break;
			}
			default:
            {
				exception = [NSException exceptionWithName:@"InvalidHeader" reason:@"InvalidField" userInfo:nil];
            }
		}
        if (exception) break;
	}
    if (exception && stop)
        @throw exception;
    return exception;
}

@end
