//
//  Kdb4Node.m
//  KeePass2
//
//  Created by Qiang Yu on 2/23/10.
//  Copyright 2010 Qiang Yu. All rights reserved.
//

#import "Kdb4Node.h"
#import "Utils.h"


#define K_NOTES "Notes"
#define K_PASSWORD "Password"
#define K_TITLE "Title"
#define K_URL "URL"
#define K_USERNAME "UserName"

@interface Kdb4Group (PrivateMethods)
@end

@implementation Kdb4Group

@synthesize _uuid;
@synthesize _image;
@synthesize _title;
@synthesize _comment;
@synthesize _subGroups;
@synthesize _entries;

- (id)init
{
    if ((self = [super init]))
    {
        _image = 0xFFFFFFFF;
    }
    return self;
}

- (UIImage *)getIcon
{
    if (_image == 0xFFFFFFFF) return nil;
    UIImage *image = [UIImage imageNamed:[NSString stringWithFormat:@"%i",_image]];
    return image;
}

- (id<KdbGroup>)getParent
{
	return (Kdb4Group *)self._parent;
}

- (void)setParent:(id<KdbGroup>)parent
{
	self._parent = parent;
}

- (void)addEntry:(id<KdbEntry>)child
{
	((Node *)child)._parent = self;
	if(!_entries)
    {
		_entries = [[NSMutableArray alloc] initWithCapacity:16];
	}
	[_entries addObject:child];
}

- (void)deleteEntry:(id<KdbEntry>)child
{
	((Node*)child)._parent = nil;
	[_entries removeObject:child];
}

- (void)addSubGroup:(id<KdbGroup>)child
{
	((Node*)child)._parent = self;
	if(!_subGroups)
    {
		_subGroups = [[NSMutableArray alloc]initWithCapacity:8];
	}
	[_subGroups addObject:child];
}

- (void)deleteSubGroup:(id<KdbGroup>)child
{
	((Node*)child)._parent = nil;
	[_subGroups removeObject:child];
}

- (void)postProcess:(id<RandomStream>)rs
{
	[super postProcess:rs];
	
	NSMutableArray * nodesToRelease = [[NSMutableArray alloc]initWithCapacity:8];
	NSMutableArray * nodesToMove = [[NSMutableArray alloc]initWithCapacity:8];
	
	for (Node *n in _children)
    {
		if([n._name isEqualToString:@T_UUID]){
			self._uuid = n._text;
			[nodesToRelease addObject:n];
		}
        else if([n._name isEqualToString:@T_NAME])
        {
			self._title = n._text;
			[nodesToRelease addObject:n];
		}
        else if ([n._name isEqualToString:@T_ICONID] || [n._name isEqualToString:@T_ICON])
        {
			if ([Utils emptyString:n._text])
            {
				self._image = 0xFFFFFFFF;
			}
            else
            {
				self._image = [n._text intValue];
			}
			[nodesToRelease addObject:n];
		}
        else if ([n._name isEqualToString:@T_NOTES])
        {
			self._comment = n._text;
			[nodesToRelease addObject:n];
		}
        else if ([n._name isEqualToString:@T_GROUP])
        {
			[self addSubGroup:(id<KdbGroup>)n];
			[nodesToMove addObject:n];
		}
        else if ([n._name isEqualToString:@T_ENTRY])
        {
			[self addEntry:(id<KdbEntry>)n];
			[nodesToMove addObject:n];
		}
	}
	
	for (Node *n in nodesToRelease)
    {
		[n breakCyclcReference];
		[self removeChild:n];
	}

	for (Node *n in nodesToMove)
    {
		[self removeChild:n];
		n._parent = self;
	}

	//DLog(@"Group Title ==> %@", _title);
}

- (NSString *)description
{
	NSString * descr = [NSString stringWithFormat:@"[UUID:%@ title:%@ \ncomment:%@]", _uuid, _title, _comment];
	return descr;
}

//break cyclic references
- (void)breakCyclcReference
{
	[super breakCyclcReference];
	
	for (Node *child in _subGroups)
    {
		[child breakCyclcReference];
	}
	
	for (Node *child in _entries)
    {
		[child breakCyclcReference];
	}
}

// KDB4 is readonly so far, no need to implement these functions
- (void)setCreation:(NSDate *) date{}
- (void)setLastMod:(NSDate *) date{}
- (void)setLastAccess:(NSDate *) date{}
- (void)setExpiry:(NSDate *) date{}

@end


@interface Kdb4Entry (PrivateMethods)
- (void)processCustomAttributes:(Node *)node withRandomStream:(id<RandomStream>)rs;
@end

@implementation Kdb4Entry

@synthesize _uuid;
@synthesize _image;
@synthesize _title;
@synthesize _url;
@synthesize _username;
@synthesize _password;
@synthesize _comment;
@synthesize _customeAttributeKeys;

- (id)init
{
    if ((self = [super init]))
    {
        _image = 0xFFFFFFFF;
    }
    return self;
}

- (UIImage *)getIcon
{
    if (_image == 0xFFFFFFFF) return nil;
    UIImage *image = [UIImage imageNamed:[NSString stringWithFormat:@"%i",_image]];
    return image;
}

- (id<KdbGroup>)getParent
{
	return (Kdb4Group *)self._parent;
}

- (void)setParent:(id<KdbGroup>)parent
{
	self._parent = parent;
}

- (NSUInteger)getNumberOfCustomAttributes
{
	return [_customeAttributeKeys count];
}

- (NSString *)getCustomAttributeName:(NSUInteger)index
{
	return [_customeAttributeKeys objectAtIndex:index];
}

- (NSString *)getCustomAttributeValue:(NSUInteger)index
{
	return [_customeAttributes objectForKey:[_customeAttributeKeys objectAtIndex:index]];
}

- (void)releaseNode:(Node *)node
{
	[node breakCyclcReference];
}

- (void)processCustomAttributes:(Node *)node withRandomStream:(id<RandomStream>)rs
{
	NSString *key = nil;
	NSString *value = nil;
	
	for (Node *n in node._children)
    {
		if ([n._name isEqualToString:@T_KEY])
        {
			key = n._text;
		}
        else if ([n._name isEqualToString:@T_VALUE])
        {
			value = n._text;
		}				
	}
	
	if ([key isEqualToString:@K_NOTES])
    {
		self._comment = value;
	}
    else if ([key isEqualToString:@K_PASSWORD])
    {
		self._password = value;
	}
    else if ([key isEqualToString:@K_TITLE])
    {
		self._title = value;
	}
    else if ([key isEqualToString:@K_URL])
    {
		self._url = value;
	}
    else if ([key isEqualToString:@K_USERNAME])
    {
		self._username = value;
	}
    else
    {
		if (!_customeAttributes)
        {
			_customeAttributes = [[NSMutableDictionary alloc] initWithCapacity:4];
		}
		[_customeAttributes setObject:value forKey:key];
	}
}

- (void)postProcess:(id<RandomStream>)rs
{
	[super postProcess:rs];
	
	NSMutableArray *nodesToRelease = [[NSMutableArray alloc] initWithCapacity:8];	
	BOOL bin = NO;
	for (Node *n in _children)
    {
		if ([n._name isEqualToString:@T_UUID])
        {
			self._uuid = n._text;
			[nodesToRelease addObject:n];
		}
        else if ([n._name isEqualToString:@T_ICONID] || [n._name isEqualToString:@T_ICON])
        {
			if ([Utils emptyString:n._text])
            {
				self._image = 0xFFFFFFFF;
			}
            else
            {
				self._image = [n._text intValue];
			}
			[nodesToRelease addObject:n];			
		}
        else if ([n._name isEqualToString:@T_NOTES])
        {
			self._comment = n._text;
			[nodesToRelease addObject:n];
		}
        else if ([n._name isEqualToString:@T_STRING])
        {
			[self processCustomAttributes:n withRandomStream:rs];
			[nodesToRelease addObject:n];
		}
        else if ([n._name isEqualToString:@T_BINARY])
        {
/*
 <KeePassFile>
 <Meta>
            <Binaries>
			<Binary ID="0" Compressed="True">H4sIAAAAAAAEAOy9B2AcSZYlJi9tynt/SvVK1+B0oQiAYBMk2JBAEOzBiM3mkuwdaUcjKasqgcplVmVdZhZAzO2dvPfee++999577733ujudTif33/8/XGZkAWz2zkrayZ4hgKrIHz9+fB8/Ir73vJpmZfGDfPasKPMX2SJvvv8bJ6eLSVZPs1leV+mr46fp63Y9K6r09z7dG5fLt5/9nk+evn79avfTnfHT589H27s7O79x8v8EAAD//6ehlfxJAAAA</Binary>
 
 <Binary>
 <Key>desktop.ini</Key>
 <Value Ref="0" />
 </Binary>

 
*/
//			self._comment = n._text;
            bin = YES;
            DLog(@"%@",n._text);
//			[nodesToRelease addObject:n];
		}
        
/*
 <AutoType>
 <Enabled>True</Enabled>
 <DataTransferObfuscation>0</DataTransferObfuscation>
 <DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence>
 <Association>
 <Window>Program Manager</Window>
 <KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</KeystrokeSequence>
 </Association>
 </AutoType>
*/ 
	}
 
	[_children removeObjectsInArray:nodesToRelease];

    if (bin)
    {
        for (Node *n in _children)
            DLog(@"%@",n);
    }
    
	for (Node *n in nodesToRelease)
    {
//		[self removeChild:n];
		[n breakCyclcReference];
	}
	
	//customer attributes
	self._customeAttributeKeys = [_customeAttributes keysSortedByValueUsingSelector:@selector(caseInsensitiveCompare:)];
}

- (NSString *)description
{
	NSString * descr = [NSString stringWithFormat:@"[UUID:%@ title:%@ \nusername:%@ \npassword:%@ \nurl:%@ \ncomment:%@]",
						_uuid, _title, _username, _password, _url, _comment];
	return descr;
}

// KDB4 is readonly so far, no need to implement these functions
- (void)setCreation:(NSDate *) date{}
- (void)setLastMod:(NSDate *) date{}
- (void)setLastAccess:(NSDate *) date{}
- (void)setExpiry:(NSDate *) date{}

@end

@implementation Kdb4Tree
@synthesize _meta;

//
// return the KDB Root
//
- (id<KdbGroup>)getRoot
{
	for (Node *n in _root._children)
    {
		if ([n._name isEqualToString:@T_ROOT])
        {
			return (id<KdbGroup>)n;
		}
	}
	return nil;
}


- (id)init
{
	if ((self = [super init]))
    {
		_meta = [[NSMutableDictionary alloc] initWithCapacity:4];
	}
	return self;
}

- (NSString *)getMetaInfo:(NSString *)key
{
	NSString * value = [_meta objectForKey:key];
	if (value) return value;
	for (Node *n in _root._children)
    {
		if ([n._name isEqualToString:@T_META])
        {
			for (Node *m in n._children)
            {
				if ([m._name isEqualToString:key])
                {
					[_meta setObject:m._text forKey:key];
					break;
				}
			}
		}
		break;
	}		
	return [_meta objectForKey:key];
}

- (BOOL)isRecycleBin:(id<KdbGroup>)group
{
	return [((Kdb4Group *)group)._uuid isEqualToString:[self getMetaInfo:@T_RECYCLEBINUUID]];
}

@end


