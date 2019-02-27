//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPDSA.h"
#import "PGPMPI.h"
#import "PGPPKCSEmsa.h"
#import "PGPPartialKey.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSignaturePacket+Private.h"
#import "PGPBigNum+Private.h"
#import "PGPKey.h"

#import "PGPLogging.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

#import <openssl/err.h>
#import <openssl/ssl.h>

#import <openssl/bn.h>
#import <openssl/dsa.h>
#import <openssl/ecdsa.h>

#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@implementation PGPDSA

+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket {
    let sig = DSA_SIG_new();
    pgp_defer { if (sig) { DSA_SIG_free(sig); } };
    
    let dsa = DSA_new();
    pgp_defer { if (dsa) { DSA_free(dsa); } };

    if (!dsa || !sig) {
        return NO;
    }

    let p = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_P] bigNum] bignumRef]);
    let q = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_Q] bigNum] bignumRef]);
    let g = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_G] bigNum] bignumRef]);
    let pub_key = BN_dup([[[publicKeyPacket publicMPI:PGPMPI_Y] bigNum] bignumRef]);

    DSA_set0_pqg(dsa, p, q, g);
    DSA_set0_key(dsa, pub_key, NULL);

    let r = BN_dup([[[signaturePacket signatureMPI:PGPMPI_R] bigNum] bignumRef]);
    let s = BN_dup([[[signaturePacket signatureMPI:PGPMPI_S] bigNum] bignumRef]);

    DSA_SIG_set0(sig, r, s);

    if (!p || !q || !g || !pub_key || r || s) {
        PGPLogError(@"Missing DSA values.");
        return NO;
    }

    var hashLen = toVerify.length;
    unsigned int qlen = 0;
    if ((qlen = (unsigned int)BN_num_bytes(DSA_get0_q(dsa))) < hashLen) {
        hashLen = qlen;
    }

    if (DSA_do_verify(toVerify.bytes, (int)hashLen, sig, dsa) < 0) {
        ERR_load_crypto_strings();
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        pgp_defer { if (errBuf) { free(errBuf); } };
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        return NO;
    }

    return YES;
}

+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key {
    let dsa = DSA_new();
    pgp_defer { if (dsa) { DSA_free(dsa); } };

    if (!dsa) {
        return @[];
    }

    let signingKeyPacket = key.signingSecretKey;
    let publicKeyPacket = PGPCast(key.publicKey.primaryKeyPacket, PGPPublicKeyPacket);

    let p = BN_dup([publicKeyPacket publicMPI:PGPMPI_P].bigNum.bignumRef);
    let q = BN_dup([publicKeyPacket publicMPI:PGPMPI_Q].bigNum.bignumRef);
    let g = BN_dup([publicKeyPacket publicMPI:PGPMPI_G].bigNum.bignumRef);
    let pub_key = BN_dup([publicKeyPacket publicMPI:PGPMPI_Y].bigNum.bignumRef);
    let priv_key = BN_dup([signingKeyPacket secretMPI:PGPMPI_X].bigNum.bignumRef);

    DSA_set0_pqg(dsa, p, q, g);
    DSA_set0_key(dsa, pub_key, priv_key);

    DSA_SIG * _Nullable sig = DSA_do_sign(toSign.bytes, (int)toSign.length, dsa);
    if (!sig) {
        ERR_load_crypto_strings();
        unsigned long err_code = ERR_get_error();
        char *errBuf = calloc(512, sizeof(char));
        pgp_defer { if (errBuf) { free(errBuf); } };
        ERR_error_string(err_code, errBuf);
        PGPLogDebug(@"%@", [NSString stringWithCString:errBuf encoding:NSASCIIStringEncoding]);
        return @[];
    }

    const BIGNUM *r;
    const BIGNUM *s;
    DSA_SIG_get0(sig, &r, &s);
    let MPI_R = [[PGPMPI alloc] initWithBigNum:[[PGPBigNum alloc] initWithBIGNUM:BN_dup(r)] identifier:PGPMPI_R];
    let MPI_S = [[PGPMPI alloc] initWithBigNum:[[PGPBigNum alloc] initWithBIGNUM:BN_dup(s)] identifier:PGPMPI_S];

    return @[MPI_R, MPI_S];
}


#pragma mark - Generate

+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(const int)bits {    
    let ctx = BN_CTX_new();
    pgp_defer { if (ctx) { BN_CTX_free(ctx); } };
    let dsa = DSA_new();
    pgp_defer { if (dsa) { DSA_free(dsa); } };

    DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL);
    if (DSA_generate_key(dsa) != 1) {
        return nil;
    }

    const BIGNUM *pub_key;
    const BIGNUM *priv_key;
    DSA_get0_key(dsa, &pub_key, &priv_key);
    let bigP = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_p(dsa))];
    let bigQ = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_q(dsa))];
    let bigG = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_g(dsa))];
    // let bigR = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(DSA_get0_r(dsa))];
    let bigX = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(priv_key)];
    let bigY = [[PGPBigNum alloc] initWithBIGNUM:BN_dup(pub_key)];

    let mpiP = [[PGPMPI alloc] initWithBigNum:bigP identifier:PGPMPI_P];
    let mpiQ = [[PGPMPI alloc] initWithBigNum:bigQ identifier:PGPMPI_Q];
    let mpiG = [[PGPMPI alloc] initWithBigNum:bigG identifier:PGPMPI_G];
    // let mpiR = [[PGPMPI alloc] initWithBigNum:bigR identifier:PGPMPI_R];
    let mpiX = [[PGPMPI alloc] initWithBigNum:bigX identifier:PGPMPI_X];
    let mpiY = [[PGPMPI alloc] initWithBigNum:bigY identifier:PGPMPI_Y];

    let keyMaterial = [[PGPKeyMaterial alloc] init];
    keyMaterial.p = mpiP;
    keyMaterial.q = mpiQ;
    keyMaterial.g = mpiG;
    // keyMaterial.r = mpiR;
    keyMaterial.x = mpiX;
    keyMaterial.y = mpiY;

    return keyMaterial;
}

@end

NS_ASSUME_NONNULL_END
