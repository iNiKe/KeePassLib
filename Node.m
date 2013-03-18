//
//  Node.m
//  KeePass2
//
//  Created by Qiang Yu on 2/10/10.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import "Node.h"
#import "RandomStream.h"
#import "Base64.h"

#define A_PROTECTED "Protected"

@implementation Node

@synthesize _parent;
@synthesize _text;
@synthesize _name;


#pragma mark alloc/dealloc
- (id)initWithUTF8Name:(uint8_t *)name
{
	NSString * value = [[NSString alloc] initWithUTF8String:(const char *)name];
	self = [self initWithStringName:value];
	return self;
}

- (id)initWithStringName:(NSString *)name
{
	//DLog(@"+++ Node %@ created", name);
	if ((self = [super init]))
    {
		self._name = name;
		_text = [[NSMutableString alloc] initWithCapacity:64];
	}
	return self;
}


- (void)addChild:(Node *)child
{
	if (!_children) _children = [[NSMutableArray alloc] initWithCapacity:8];
	[_children addObject:child];
	child._parent = self;
}

- (void)removeChild:(Node *)child
{
	[_children removeObject:child];
	child._parent = nil;
}

- (void)addAttribute:(NSString *)key value:(NSString *)value
{
	if(!_attributes) _attributes = [[NSMutableDictionary alloc] initWithCapacity:2];
	[_attributes setObject:value forKey:key];
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"%@ <%@>%@<%@/>",[super description],_name,_text, _name];
}

- (NSArray *)_children
{
	return _children;
}

- (NSDictionary *)_attributes
{
	return _attributes;
}

//break cyclic references
- (void)breakCyclcReference
{
	self._parent = nil;
	for (Node *child in _children)
    {
		[child breakCyclcReference];
	}
}

//do nothing by default
- (void)postProcess:(id<RandomStream>)rs
{
    if ([_children count] != 0)
    {
        NSString *txt = [_text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (txt.length > 0)
        {
            if (txt.length < _text.length)
                DLog(@"%@",txt);
        }
        if (txt.length == 0)
            _text = nil;
        else
            _text = [NSMutableString stringWithString:txt];
    }
	if ([(NSString *)[_attributes objectForKey:@A_PROTECTED] boolValue])
    {
		NSMutableData *data = [[NSMutableData alloc] initWithCapacity:[_text length]];
		[Base64 decode:_text to:data];
		[self._text setString:[rs xor:data]];
	}
}

@end
