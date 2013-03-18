//
//  Kdb4Node.h
//  KeePass2
//
//  Created by Qiang Yu on 2/23/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Node.h"
#import "Kdb.h"
#import "Tree.h"

@interface Kdb4Group : Node<KdbGroup>
{
	NSString * _uuid;
	uint32_t _image;
	NSString * _title;
	NSString * _comment;
	NSMutableArray * _subGroups;
	NSMutableArray * _entries;
}

@property(nonatomic, strong) NSString * _uuid;
@property(nonatomic, assign) uint32_t _image;
@property(nonatomic, strong, getter=getGroupName, setter=setGroupName:) NSString * _title;
@property(nonatomic, strong) NSString * _comment;
@property(nonatomic, strong, getter=getSubGroups) NSMutableArray * _subGroups;
@property(nonatomic, strong, getter=getEntries) NSMutableArray * _entries;

@end


@interface Kdb4Entry: Node<KdbEntry>
{
	NSString * _uuid;
	uint32_t _image;
	NSString * _title;
	NSString * _url;
	NSString * _username;
	NSString * _password;
	NSString * _comment;
	
	NSArray * _customeAttributeKeys;	
	NSMutableDictionary * _customeAttributes;
}

@property(nonatomic, strong) NSString * _uuid;
@property(nonatomic, assign) uint32_t _image;
@property(nonatomic, strong, getter=getEntryName, setter=setEntryName:) NSString * _title;
@property(nonatomic, strong, getter=getUserName, setter=setUserName:) NSString * _username;
@property(nonatomic, strong, getter=getPassword, setter=setPassword:) NSString * _password;
@property(nonatomic, strong, getter=getComments, setter=setComments:) NSString * _comment;
@property(nonatomic, strong, getter=getURL, setter=setURL:) NSString * _url;
@property(nonatomic, strong) NSArray * _customeAttributeKeys;

- (UIImage *)getIcon;

@end


@interface Kdb4Tree:Tree<KdbTree>
{
	NSMutableDictionary * _meta;
}

@property(nonatomic, strong) NSMutableDictionary * _meta;

- (NSString *)getMetaInfo:(NSString *)key;

@end
