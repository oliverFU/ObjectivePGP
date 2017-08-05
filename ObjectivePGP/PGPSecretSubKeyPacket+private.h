//
//  PGPSecretSubKeyPacket+private.h
//  ObjectivePGP
//
//  Created by Oliver Wiese on 04.08.17.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//



@interface PGPSecretKeyPacket ()

- (instancetype)init: (NSArray*) secretMPIArray publicMPIArray: (NSArray*) publicMPIArray;

@end
