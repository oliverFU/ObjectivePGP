//
//  PGPTestUtils.m
//  ObjectivePGPTests
//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPTestUtils.h"
#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPTestUtils

+ (nullable NSBundle *)filesBundle {
    NSString *path = [[NSBundle bundleForClass:self.class] pathForResource:@"testfiles" ofType:@"bundle"];
    return [NSBundle bundleWithPath:path];
}

+ (NSString *)pathToBundledFile:(NSString *)fileName {
    NSBundle *bundle = self.filesBundle;
    return [bundle pathForResource:fileName.stringByDeletingPathExtension ofType:fileName.pathExtension];
}

+ (NSArray<PGPKey *> *)readKeysFromPath:(NSString *)fileName {
    NSString *path = [self pathToBundledFile:fileName];
    NSError *error;
    NSArray<PGPKey *> *keys = [ObjectivePGP readKeysFromPath:path error:&error];
    NSAssert(error == nil, @"Can't read file: %@", path);
    return keys;
}


@end

NS_ASSUME_NONNULL_END
