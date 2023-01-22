pragma circom 2.0.0;

include "circomlib/babyjub.circom";
include "circomlib/escalarmulany.circom";
include "circomlib/poseidon.circom";

template TpkeEncryptionDual() {
    signal input k;
    signal input M1x;
    signal input M1y;
    signal input M2x;
    signal input M2y;
    signal input nonce;

    signal input PKx;
    signal input PKy;
    
    // public
    signal output C1x;
    signal output C1y;
    signal output C2x;
    signal output C2y;
    signal output C3x;
    signal output C3y;

    signal Ax;
    signal Ay;

    var i;

    var G[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    component k2bits = Num2Bits(256);
    k2bits.in <== k;

    component mulFixC1 = EscalarMulFix(256, G);
    for (i=0; i<256; i++) {
        mulFixC1.e[i] <== k2bits.out[i];
    }

    // output C1
    C1x <== mulFixC1.out[0];
    C1y <== mulFixC1.out[1];

    // check k*pk
    component mulAny = EscalarMulAny(256);
    for (i=0; i<256; i++) {
        mulAny.e[i] <== k2bits.out[i];
    }
    mulAny.p[0] <== PKx;
    mulAny.p[1] <== PKy;

    //check C2
    component x2bits = Num2Bits(256);
    x2bits.in <== mulFixC1.out[0];
    component mulAnyC2 = EscalarMulAny(256);
    for (i=0; i<256; i++) {
        mulAnyC2.e[i] <== x2bits.out[i];
    }
    mulAnyC2.p[0] <== M1x;
    mulAnyC2.p[1] <== M1y;

    C2x <== mulAnyC2.out[0];
    C2y <== mulAnyC2.out[1];
    
    //check C3
    component y2bits = Num2Bits(256);
    y2bits.in <== mulFixC1.out[1] + nonce;
    component mulAnyC3 = EscalarMulAny(256);
    for (i=0; i<256; i++) {
        mulAnyC3.e[i] <== y2bits.out[i];
    }
    mulAnyC3.p[0] <== M2x;
    mulAnyC3.p[1] <== M2y;
    

    C3x <== mulAnyC3.out[0];
    C3y <== mulAnyC3.out[1];
}

component main = TpkeEncryptionDual();
