// Verify whether the given ciphertext is the threshold public key
// encryption of the specified value.

pragma circom 2.0.0;

include "circomlib/babyjub.circom";
include "circomlib/escalarmulany.circom";

template TpkeEncryption() {
    signal input k;
    signal input Mx;
    signal input My;
    
    // public
    signal input C1x;
    signal input C1y;
    signal input C2x;
    signal input C2y;

    signal input Bx;
    signal input By;

    signal input PKx;
    signal input PKy;

    signal Ax;
    signal Ay;

    var i;

    var G[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    component check = BabyCheck();
    check.x <== Mx;
    check.y <== My;

    component k2bits = Num2Bits(256);
    k2bits.in <== k;

    component mulFixC1 = EscalarMulFix(256, G);
    for (i=0; i<256; i++) {
        mulFixC1.e[i] <== k2bits.out[i];
    }

    // check C1
    C1x === mulFixC1.out[0];
    C1y === mulFixC1.out[1];

    // check k*pk
    component mulAny = EscalarMulAny(256);
    for (i=0; i<256; i++) {
        mulAny.e[i] <== k2bits.out[i];
    }
    mulAny.p[0] <== PKx;
    mulAny.p[1] <== PKy;

    //check C2
    component addMsg = BabyAdd();
    addMsg.x1 <== Mx;
    addMsg.y1 <== My;
    addMsg.x2 <== mulAny.out[0];
    addMsg.y2 <== mulAny.out[1];

    C2x === addMsg.xout;
    C2y === addMsg.yout;
    
    //check msg
    component my2bits = Num2Bits(256);
    my2bits.in <== My;

    component mulFixMy = EscalarMulFix(256, G);
    for (i=0; i<256; i++) {
        mulFixMy.e[i] <== my2bits.out[i];
    }

    // check msg
    Bx === mulFixMy.out[0];
    By === mulFixMy.out[1];

}

component main {public [C1x, C1y, C2x, C2y, Bx, By, PKx, PKy]} = TpkeEncryption();
// component main  = TpkeEncryption();