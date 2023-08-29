pragma circom 2.0.0;

include "circomlib/babyjub.circom";
include "circomlib/escalarmulany.circom";
include "circomlib/poseidon.circom";
include "check_point.circom";

template AppKey() {
    // public input
    signal input key;
    signal input ss;
    // TPKE pubkey
    signal input Yy;

    // TPKE C2
    signal input C2y;

    //private input
    signal input Yx;
    signal input C2x;

    signal input k; // CA's pubkey
    signal input x;

    var i;
    var G[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    // id <-- ss & 1461501637330902918203684832716283019655932542975;
    // Ys <-- (ss >> 160) & 1;
    // C2s <-- (ss >> 161) & 1;

    component ss2bits = Num2Bits(162);
    ss2bits.in <== ss;

    component YCheck = PointCheck();
    YCheck.s <== ss2bits.out[160];
    YCheck.x <== Yx;
    YCheck.y <== Yy;

    component C2Check = PointCheck();
    C2Check.s <== ss2bits.out[161];
    C2Check.x <== C2x;
    C2Check.y <== C2y;
    // calculate id
    var id = 0;
    var e2=1;
    for (i = 0; i<160; i++) {
        id += ss2bits.out[i] * e2;
        e2 = e2+e2;
    }
    // calculate X
    component x2bits = Num2Bits(256);
    x2bits.in <== x;

    component mulFixX = EscalarMulFix(256, G);
    for (i=0; i<256; i++) {
        mulFixX.e[i] <== x2bits.out[i];
    }

    // check k*pk
    component k2bits = Num2Bits(256);
    k2bits.in <== k;
    component mulAny = EscalarMulAny(256);
    for (i=0; i<256; i++) {
        mulAny.e[i] <== k2bits.out[i];
    }
    mulAny.p[0] <== Yx;
    mulAny.p[1] <== Yy;

    component addX = BabyAdd();
    addX.x1 <== mulFixX.out[0];
    addX.y1 <== mulFixX.out[1];
    addX.x2 <== mulAny.out[0];
    addX.y2 <== mulAny.out[1];

    C2x === addX.xout;
    C2y === addX.yout;

    component hash = Poseidon(2);
    hash.inputs[0] <== x;
    hash.inputs[1] <== id;

    key === hash.out;
    
}

component main {public [key, ss, Yy, C2y] } = AppKey();

