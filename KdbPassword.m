//
//  Password.m
//  KeePass2
//
//  Created by Qiang Yu on 1/5/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#import "KdbPassword.h"
#import "Utils.h"
#import "Base64.h"

@interface KdbPassword(PrivateMethods)
- (void)transformKeyHash:(uint8_t *)keyHash result:(uint8_t *)result;
@end

@implementation KdbPassword

@synthesize _masterSeed;
@synthesize _transformSeed;
@synthesize _rounds;
@synthesize finished = _finished;

- (void)transformKeyHash:(uint8_t *)keyHash result:(uint8_t *)result
{
	size_t tmp;
	
	CCCryptorRef cryptorRef = nil;
	CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES128,kCCOptionECBMode,_transformSeed._bytes,
					kCCKeySizeAES256, nil,&cryptorRef);
	
	for(int i=0; i<_rounds; i++){
		CCCryptorUpdate(cryptorRef, keyHash, 32, keyHash, 32, &tmp);
	}
	
	// no need to call CCCryptorFinal 	
	CCCryptorRelease(cryptorRef);
	
	CC_SHA256(keyHash, 32, result);	
}

- (ByteBuffer *)createFinalKey32ForPasssword:(NSString *)password coding:(NSStringEncoding)coding keyFile:(NSString *)keyFile kdbVersion:(uint8_t)ver
{
	ByteBuffer *pwd = [Utils createByteBufferForString:password coding:coding];
	uint8_t pwdHash[32], keyHash[32];
	CC_SHA256(pwd._bytes, pwd._size, pwdHash);
		
	///////////////////////////////////////////////////
	//
	// !!! NOTE: KDB3 may not need the extra hash below
	//
	///////////////////////////////////////////////////
    BOOL keyLoaded = [self loadKeyFile:keyFile hash:keyHash];
	if (ver == 4)
    {
        CC_SHA256_CTX ctxPw;
        CC_SHA256_Init(&ctxPw);
        CC_SHA256_Update(&ctxPw, pwdHash, 32);
        if (keyLoaded)
            CC_SHA256_Update(&ctxPw, keyHash, 32);
        CC_SHA256_Final(keyHash, &ctxPw);
    }
    else
    {
        if (keyLoaded)
        {
            CC_SHA256_CTX ctxPw;
            CC_SHA256_Init(&ctxPw);
            CC_SHA256_Update(&ctxPw, pwdHash, 32);
            CC_SHA256_Update(&ctxPw, keyHash, 32);
            CC_SHA256_Final(keyHash, &ctxPw);
        }
        else
            memcpy(keyHash, pwdHash, 32);
    }
	
	ByteBuffer *rv = [[ByteBuffer alloc] initWithSize:32];
    if (ver == 1)
    {
        memcpy(rv._bytes, keyHash, 32);
    }
    else
    {
        //step 1 transform the key
        uint8_t transformed[32];
        [self transformKeyHash:keyHash result:transformed];
        
        //step 2 hash the transform result
        CC_SHA256_CTX ctx;
        CC_SHA256_Init(&ctx);
        CC_SHA256_Update(&ctx, _masterSeed._bytes, _masterSeed._size);
        CC_SHA256_Update(&ctx, transformed, 32);
        CC_SHA256_Final(rv._bytes, &ctx);
    }
    return rv;
}

- (BOOL)loadKeyFile:(NSString *)filename hash:(uint8_t *)hash
{
    if (!hash || !filename) return NO;
    if ([self loadXmlKeyFile:filename hash:hash])
        return YES;
    if ([self loadBinaryKeyFile:filename hash:hash])
        return YES;
    if ([self loadHexKeyFile:filename hash:hash])
        return YES;
    if ([self loadHashedKeyFile:filename hash:hash])
        return YES;
    return NO;
}

- (BOOL)loadXmlKeyFile:(NSString *)filename hash:(uint8_t *)hash
{
    if (!hash || !filename) return NO;
    
    NSXMLParser *parser = [[NSXMLParser alloc] initWithContentsOfURL:[NSURL fileURLWithPath:filename]];
    [parser setDelegate:self];
    [parser parse];
    
    // ждем, пока идет загрука и парсинг
    while (!_finished)
        sleep(1);

    if (!_hasError && ([_keyData length] == 32))
    {
        memcpy(hash, _keyData.bytes, 32);
        return YES;
    }
    
    return NO;
}

- (BOOL)loadBinaryKeyFile:(NSString *)filename hash:(uint8_t *)hash
{
    if (!hash || !filename) return NO;
    FILE *f = fopen([filename UTF8String], "rb");
    if (f)
    {
        fseek(f, 0, SEEK_END); long size = ftell(f);
        if (size == 32)
        {
            fseek(f, 0, SEEK_SET);
            size_t readed = fread(hash, 1, 32, f);
            if (readed == 32)
            {
                return YES;
            }
        }
        fclose(f);
    }
    return NO;
}

- (BOOL)loadHexKeyFile:(NSString *)filename hash:(uint8_t *)hash
{
    if (!hash || !filename) return NO;
    FILE *f = fopen([filename UTF8String], "rb");
    if (f)
    {
        fseek(f, 0, SEEK_END); long size = ftell(f);
        if (size == 64)
        {
            uint8_t hexBuf[64];
            fseek(f, 0, SEEK_SET);
            size_t readed = fread(&hexBuf, 1, 64, f);
            if (readed == 64)
            {
                uint8_t y = 0;
                for (int i = 0; i < 64; i++)
                {
                    unsigned char c = hexBuf[i];
                    uint8_t x = 0;
                    if (c >= '0' && c <= '9')
                        x = c - '0';
                    else if (c >= 'a' && c <= 'f')
                        x = 10 + c - 'a';
                    else if (c >= 'A' && c <= 'F')
                        x = 10 + c - 'A';
                    else
                        return NO;
                    if ((i+1) % 2 == 0)
                    {
                        hash[i/2] = ((y << 4) & 0xF0) | (x & 0x0F);
                    }
                    else
                        y = x;
                }
                return YES;
            }
        }
        fclose(f);
    }
    return NO;
}

- (BOOL)loadHashedKeyFile:(NSString *)filename hash:(uint8_t *)hash
{
    if (!hash || !filename) return NO;
    BOOL result = NO;
    FILE *f = fopen([filename UTF8String], "rb");
    if (f)
    {
        fseek(f, 0, SEEK_END); long size = ftell(f);
        if (size > 0)
        {
            uint8_t buff[1024];
            CC_SHA256_CTX ctx;
            CC_SHA256_Init(&ctx);
            fseek(f, 0, SEEK_SET);
            while (!feof(f)) {
                size_t readed = fread(&buff, 1, 1024, f);
                if (readed > 0)
                {
                    CC_SHA256_Update(&ctx, buff, readed);
                    result = YES;
                }
                if (readed != 1024)
                    break;
            }
            if (result)
                CC_SHA256_Final(hash, &ctx);
        }
        fclose(f);
    }
    return result;
}


#pragma mark NSXMLParserDelegate

// документ начал парситься
- (void)parserDidStartDocument:(NSXMLParser *)parser
{
    _finished = NO; _isKeyfile = NO; _isKey = NO; _elements = [NSMutableArray array]; _keyData = nil;
//    DLog(@"parserDidStartDocument");
}

// парсинг окончен
- (void)parserDidEndDocument:(NSXMLParser *)parser
{
    _finished = YES;
//    NSLog(@"parserDidEndDocument");
}

// если произошла ошибка парсинга
- (void)parser:(NSXMLParser *)parser parseErrorOccurred:(NSError *)parseError
{
    _finished = YES; _hasError = YES;
//    NSLog(@"parseError = %@",parseError);
}

// если произошла ошибка валидации
- (void)parser:(NSXMLParser *)parser validationErrorOccurred:(NSError *)validationError
{
    _finished = YES; _hasError = YES;
//    NSLog(@"validationError = %@",validationError);
}

// встретили новый элемент
- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName attributes:(NSDictionary *)attributeDict
{
//    NSLog(@"[START] elementName = %@ namespaceURI = %@ qName = %@ attributes = %@",elementName,namespaceURI,qName,attributeDict);
    if ( [elementName isKindOfClass:[NSString class]] && (elementName.length > 0) )
        [_elements addObject:elementName];
}

- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName
{
//    NSLog(@"[  END] elementName = %@ namespaceURI = %@ qName = %@",elementName,namespaceURI,qName);
    if ( [elementName isKindOfClass:[NSString class]] && (elementName.length > 0) )
    {
//        [_elements removeLastObject];
        for (int i = _elements.count-1; i >= 0; i--)
        {
            if ([[_elements objectAtIndex:i] caseInsensitiveCompare:elementName] == NSOrderedSame)
            {
                for (int j = 0; j < _elements.count - i; j++) {
                    [_elements removeLastObject];
                }
                break;
            }
        }
    }
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string
{
//    NSLog(@"foundCharacters = %@",string);
    if (string.length > 0)
    {
        if (_elements.count == 3)
        {
            if ( ([[_elements objectAtIndex:0] caseInsensitiveCompare:@"KeyFile"] == NSOrderedSame) &&
                 ([[_elements objectAtIndex:1] caseInsensitiveCompare:@"Key"] == NSOrderedSame) &&
                 ([[_elements objectAtIndex:2] caseInsensitiveCompare:@"Data"] == NSOrderedSame) )
            {
                _keyData = [NSMutableData data];
                [Base64 decode:string to:_keyData];
                DLog(@"keyData: %@ (%i bytes)",string,_keyData.length);
            }
        }
    }
}

@end
