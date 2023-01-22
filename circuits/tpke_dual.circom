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
    component addMsg1 = BabyAdd();
    addMsg1.x1 <== M1x;
    addMsg1.y1 <== M1y;
    addMsg1.x2 <== mulAny.out[0];
    addMsg1.y2 <== mulAny.out[1];

    C2x <== addMsg1.xout;
    C2y <== addMsg1.yout;
    
    //check C3
    component hash = Poseidon(3);
    hash.inputs[0] <== mulAny.out[0];
    hash.inputs[1] <== mulAny.out[1];
    hash.inputs[2] <== nonce;

    component h2bits = Num2Bits(256);
    h2bits.in <== hash.out;
    component mulFixC3 = EscalarMulFix(256, G);
    for (i=0; i<256; i++) {
        mulFixC3.e[i] <== h2bits.out[i];
    }

    component addMsg2 = BabyAdd();
    addMsg2.x1 <== M2x;
    addMsg2.y1 <== M2y;
    addMsg2.x2 <== mulFixC3.out[0];
    addMsg2.y2 <== mulFixC3.out[1];

    C3x <== addMsg2.xout;
    C3y <== addMsg2.yout;
}

// component main = TpkeEncryptionDual();
