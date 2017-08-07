//
//  PGPKey.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKey.h"
#import "PGPKey+Private.h"
#import "PGPSubKey.h"
#import "PGPLogging.h"
#import "PGPMacros.h"

#import "PGPSecretKeyPacket.h"
#import "PGPSecretKeyPacket+Private.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPSignatureSubpacket+Private.h"
#import "PGPRSA.h"

#import "PGPMacros.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPKey

- (instancetype)initWithSecretKey:(nullable PGPPartialKey *)secretKey publicKey:(nullable PGPPartialKey *)publicKey {
    if ((self = [super init])) {
        _secretKey = secretKey;
        _publicKey = publicKey;
    }
    return self;
}

- (BOOL)isSecret {
    return self.secretKey != nil;
}

- (BOOL)isPublic {
    return self.publicKey != nil;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@, publicKey: %@, secretKey: %@", super.description, self.publicKey.keyID, self.secretKey.keyID];
}

- (PGPKeyID *)keyID {
    return self.publicKey.keyID ?: self.secretKey.keyID;
}

- (PGPFingerprint *)fingerprint {
    return self.publicKey.fingerprint ?: self.secretKey.fingerprint;
}

- (nullable PGPSecretKeyPacket *)signingSecretKey {
    if (!self.secretKey) {
        PGPLogDebug(@"Need secret key to sign");
        return nil;
    }

    // find secret key based on the public key signature (unless self signed secret key)
    let signingPacket = PGPCast(self.secretKey.signingKeyPacket, PGPSecretKeyPacket);
    if (!signingPacket) {
        PGPLogWarning(@"Need secret key to sign");
    }

    return signingPacket;
}

+ (nullable PGPKey *)generateKeyForUserID:(NSString *)userID algorithm:(PGPPublicKeyAlgorithm)algorithm bits:(int)bits {
    PGPAssertClass(userID, NSString);

    let MPIs = [PGPRSA generateNewKeyMPIs:bits algorithm:algorithm];

    // Secret
    let secretKeyPacket = [[PGPSecretKeyPacket alloc] init];
    secretKeyPacket.version = 0x04;
    secretKeyPacket.publicKeyAlgorithm = algorithm;
    secretKeyPacket.s2kUsage = PGPS2KUsageEncryptedAndHashed;
    secretKeyPacket.s2k = [[PGPS2K alloc] initWithSpecifier:PGPS2KSpecifierSalted hashAlgorithm:PGPHashSHA1];
    secretKeyPacket.symmetricAlgorithm = PGPSymmetricAES256;
    NSUInteger blockSize = [PGPCryptoUtils blockSizeOfSymmetricAlhorithm:secretKeyPacket.symmetricAlgorithm];
    secretKeyPacket.ivData = [NSMutableData dataWithLength:blockSize];
    secretKeyPacket.publicMPIArray = [[MPIs filteredSetUsingPredicate:[NSPredicate predicateWithFormat:@"SELF.identifier IN %@",@[PGPMPI_N, PGPMPI_E, PGPMPI_D, PGPMPI_P, PGPMPI_Q, PGPMPI_U]]] allObjects];

    // public
    let publicKeyPacket = [[PGPPublicKeyPacket alloc] init];
    publicKeyPacket.version = 0x04;
    publicKeyPacket.publicKeyAlgorithm = algorithm;
    publicKeyPacket.createDate = NSDate.date;
    publicKeyPacket.publicMPIArray = [[MPIs filteredSetUsingPredicate:[NSPredicate predicateWithFormat:@"SELF.identifier IN %@",@[PGPMPI_N, PGPMPI_E]]] allObjects];

    // user id
    let userIDPacket = [[PGPUserIDPacket alloc] initWithUserID:userID];

    // signature
    let publicKeySignaturePacket = [[PGPSignaturePacket alloc] init];
    publicKeySignaturePacket.version = 0x04;
    publicKeySignaturePacket.type = PGPSignaturePositiveCertificationUserIDandPublicKey;
    publicKeySignaturePacket.publicKeyAlgorithm = secretKeyPacket.publicKeyAlgorithm;
    publicKeySignaturePacket.hashAlgoritm = PGPHashSHA1;

    let creationTimeSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeSignatureCreationTime andValue:NSDate.date];
    let issuerKeyIDSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeIssuerKeyID andValue:publicKeyPacket.keyID];
    let keyFlagsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyFlags andValue:@[@(PGPSignatureFlagAllowSignData), @(PGPSignatureFlagAllowCertifyOtherKeys)]];
    let preferredHashAlgorithmsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredHashAlgorithm andValue:@[@(PGPHashSHA256), @(PGPHashSHA1), @(PGPHashSHA384), @(PGPHashSHA512), @(PGPHashSHA224)]];
    let preferredSymetricAlgorithmsSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredSymetricAlgorithm andValue:@[@(PGPSymmetricAES256), @(PGPSymmetricAES192), @(PGPSymmetricAES128), @(PGPSymmetricCAST5), @(PGPSymmetricTripleDES)]];
    let preferredPreferredCompressionSubpacket = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypePreferredCompressionAlgorithm andValue:@[@(PGPCompressionZLIB), @(PGPCompressionBZIP2), @(PGPCompressionZIP)]];
    let keyFeatures = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeFeatures andValue:@[@(PGPFeatureModificationDetection)]];
    let keyServerPreferences = [[PGPSignatureSubpacket alloc] initWithType:PGPSignatureSubpacketTypeKeyServerPreference andValue:@[@(PGPKeyServerPreferenceNoModify)]];

    publicKeySignaturePacket.hashedSubpackets = @[creationTimeSubpacket, keyFlagsSubpacket, preferredHashAlgorithmsSubpacket, preferredSymetricAlgorithmsSubpacket, preferredPreferredCompressionSubpacket, keyFeatures, keyServerPreferences];
    publicKeySignaturePacket.unhashedSubpackets = @[issuerKeyIDSubpacket];

    NSError *error;
    let publicKeyPacketData = [publicKeyPacket export:&error];
    // let secretKeyPacketData = [secretKeyPacket export:&error];
    let userIDPacketData = [userIDPacket export:&error];
    let publicKeySignaturePacketData = [publicKeySignaturePacket export:&error];

    let outputData = [NSMutableData data];
    [outputData appendData:publicKeyPacketData];
    [outputData appendData:userIDPacketData];
    [outputData appendData:publicKeySignaturePacketData];
    // [outputData appendData:secretKeyPacketData];
    [outputData writeToFile:@"/Users/marcinkrzyzanowski/Devel/ObjectivePGP/test-key.dat" atomically:YES];


    return nil;
}

- (BOOL)isEqual:(id)object {
    if (object == self) {
        return YES;
    }

    let other = PGPCast(object, PGPKey);
    if (!other) {
        return NO;
    }

    BOOL result = YES;
    if (self.secretKey) {
        result = [self.secretKey isEqual:other.secretKey];
    }

    if (result && self.publicKey) {
        result = [self.publicKey isEqual:other.publicKey];
    }

    return result;
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = 7;
    result = prime * result + self.secretKey.hash;
    result = prime * result + self.publicKey.hash;
    return result;
}

#pragma mark - PGPExportable

- (nullable NSData *)export:(NSError *__autoreleasing _Nullable *)error {
    NSMutableData *exportData = [NSMutableData data];
    if (self.publicKey) {
        let exported = [self.publicKey export:error];
        if (exported) {
            [exportData appendData:exported];
        }
    }

    if (self.secretKey) {
        let exported = [self.secretKey export:error];
        if (exported) {
            [exportData appendData:exported];
        }
    }
    return exportData;
}

@end

NS_ASSUME_NONNULL_END
