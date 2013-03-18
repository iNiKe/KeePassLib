//
//  KDB.h
//  KeePass2
//
//  Created by Qiang Yu on 1/1/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define DEF_ROUNDS  600

#define KEEPASS_SIG     (0x9AA2D903)
#define KDB3_SIG2       (0xB54BFB65)
#define KDB4_PRE_SIG2   (0xB54BFB66)
#define KDB4_SIG2       (0xB54BFB67)

#define FLAG_SHA2     1
#define FLAG_RIJNDAEL 2
#define FLAG_ARCFOUR  4
#define FLAG_TWOFISH  8

/// <summary>
/// File version of files saved by the current <c>KdbxFile</c> class.
/// KeePass 2.07 has version 1.01, 2.08 has 1.02, 2.09 has 2.00,
/// 2.10 has 2.02, 2.11 has 2.04, 2.15 has 3.00, 2.20 has 3.01.
/// The first 2 bytes are critical (i.e. loading will fail, if the
/// file version is too high), the last 2 bytes are informational.
/// </summary>

#define KDB3_VER  (0x00030002)
#define KDB3_HEADER_SIZE (124)

#define KDB4_VER  (0x00030001)
#define KDB4_HEADER_SIZE (124)

#define FILE_VERSION_CRITICAL_MASK  0xFFFF0000

@protocol KdbEntry;

@protocol KdbGroup<NSObject>
- (id<KdbGroup>)getParent;
- (void)setParent:(id<KdbGroup>)parent;

- (UIImage *)getIcon;

- (NSString*)getGroupName;
- (void)setGroupName:(NSString *)groupName;

- (NSArray *)getEntries;
- (void)addEntry:(id<KdbEntry>)child;
- (void)deleteEntry:(id<KdbEntry>)child;

- (NSArray *)getSubGroups;
- (void)addSubGroup:(id<KdbGroup>)child;
- (void)deleteSubGroup:(id<KdbGroup>)child;

- (void)setCreation:(NSDate *)date;
- (void)setLastMod:(NSDate *)date;
- (void)setLastAccess:(NSDate *)date;
- (void)setExpiry:(NSDate *)date;

@end

@protocol KdbEntry<NSObject>
- (id<KdbGroup>)getParent;
- (void)setParent:(id<KdbGroup>)parent;

- (UIImage *)getIcon;

- (NSString*)getEntryName;
- (void)setEntryName:(NSString *)entryName;

- (NSString*)getUserName;
- (void)setUserName:(NSString *)userName;

- (NSString*)getPassword;
- (void)setPassword:(NSString *)password;

- (NSString*)getURL;
- (void)setURL:(NSString *)url;

- (NSString*)getComments;
- (void)setComments:(NSString *)comments;

- (NSUInteger)getNumberOfCustomAttributes;
- (NSString *)getCustomAttributeName:(NSUInteger)index;
- (NSString *)getCustomAttributeValue:(NSUInteger)index;

- (void)setCreation:(NSDate *)date;
- (void)setLastMod:(NSDate *)date;
- (void)setLastAccess:(NSDate *)date;
- (void)setExpiry:(NSDate *)date;

/* TODO: 
-(NSDate*)getCreationDate;
-(NSDate*)getLastAccessDate;
-(NSDate*)getModificationDate;
-(NSDate*)getExpiry;

-(void)setCreationDateYear:(int)yyyy month:(int)mm day:(int)dd hour:(int)hh minutes:(int)mi seconds:(int)ss;
-(void)setLastAccessDate:(int)yyyy month:(int)mm day:(int)dd hour:(int)hh minutes:(int)mi seconds:(int)ss;
-(void)setModificationDate:(int)yyyy month:(int)mm day:(int)dd hour:(int)hh minutes:(int)mi seconds:(int)ss;
-(void)setExpiry:(int)yyyy month:(int)mm day:(int)dd hour:(int)hh minutes:(int)mi seconds:(int)ss;
*/

@end

@protocol KdbTree<NSObject>
- (id<KdbGroup>)getRoot;
- (BOOL)isRecycleBin:(id<KdbGroup>)group;
@end
