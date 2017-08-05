//
//  PGPSecretSubKeyPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 07/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  A Secret-Subkey packet (tag 7) is the subkey analog of the Secret
//  Key packet and has exactly the same format.

#import "PGPSecretSubKeyPacket.h"
#import "PGPSecretSubKeyPacket+private.h"
#import <openssl/rsa.h>
#import "PGPMPI.h"
#import "PGPBigNum.h"
#import "PGPBigNum+Private.h"

@implementation PGPSecretSubKeyPacket

+ (PGPSecretSubKeyPacket *) generateRSASecretSubKeyPacket: (int) bits{
    RSA* rsa = RSA_new();
    BIGNUM* e_bignum = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    
    BN_set_word(e_bignum, 65537UL);
    RSA_generate_key_ex(rsa, bits, e_bignum, nil);
    
    PGPBigNum* n = [[PGPBigNum alloc] initWithBIGNUM: rsa->n];
    PGPBigNum* e = [[PGPBigNum alloc] initWithBIGNUM: rsa->e];
    PGPBigNum* d = [[PGPBigNum alloc] initWithBIGNUM: rsa->d];
    PGPBigNum* p = [[PGPBigNum alloc] initWithBIGNUM: rsa->p];
    PGPBigNum* q = [[PGPBigNum alloc] initWithBIGNUM: rsa->q];
    
    
    PGPMPI* pgpmpi_n = [[PGPMPI alloc] initWithBigNum: n identifier: PGPMPI_N];
    PGPMPI* pgpmpi_e = [[PGPMPI alloc] initWithBigNum: e identifier: PGPMPI_E];
    
    PGPMPI* pgpmpi_d = [[PGPMPI alloc] initWithBigNum: d identifier: PGPMPI_D];
    PGPMPI* pgpmpi_p = [[PGPMPI alloc] initWithBigNum: p identifier: PGPMPI_P];
    PGPMPI* pgpmpi_q = [[PGPMPI alloc] initWithBigNum: q identifier: PGPMPI_Q];
    BIGNUM* u_bignum = BN_new();
    u_bignum = BN_mod_inverse(u_bignum,rsa->p, rsa->q, ctx);
    PGPBigNum* u = [[PGPBigNum alloc] initWithBIGNUM: u_bignum];
    
    
    PGPMPI* pgpmpi_u = [[PGPMPI alloc] initWithBigNum: u identifier: PGPMPI_U];
    
    // sk: d, p,q, u (RFC4480 5.1.3)
    NSArray *sk_mpi = [NSArray arrayWithObjects: pgpmpi_d, pgpmpi_p, pgpmpi_q,pgpmpi_u, nil];
    // pk: n,e (RFC4480 5.5.2)
    NSArray *pk_mpi = [NSArray arrayWithObjects:pgpmpi_n, pgpmpi_e, nil];
    
    PGPSecretSubKeyPacket* sk = [[PGPSecretSubKeyPacket alloc] init:sk_mpi publicMPIArray: pk_mpi];
    return sk;
}


- (PGPPacketTag)tag {
    return PGPSecretSubkeyPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
    return [super parsePacketBody:packetBody error:error];
}

@end
