//
//  Kdb3Persist.h
//  KeePass2
//
//  Created by Qiang Yu on 2/22/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AESEncryptSource.h"
#import "Kdb4Node.h"

@interface Kdb4Persist : NSObject
{
	id<KdbTree> _tree;
	AESEncryptSource * _enc;
	NSInteger _groupId;
}

@property(nonatomic, strong) id<KdbTree> _tree;
@property(nonatomic, strong) AESEncryptSource * _enc;

- (id)initWithTree:(id<KdbTree>)tree andDest:(AESEncryptSource *)dest;
- (void)persist;

@end
