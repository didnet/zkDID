pragma circom 2.0.0;

include "circomlib/binsub.circom";
include "circomlib/bitify.circom";

template Cmp(n) {
    signal input in1;
    signal input in2;
    signal output out;

    var i;

    component v2bits1 = Num2Bits(n);
    v2bits1.in <== in1;
    component v2bits2 = Num2Bits(n);
    v2bits2.in <== in2;

    component v1SubV2 = BinSub(n);

    for(i=0; i < n; i++) {
        v1SubV2.in[0][i] <== v2bits1.out[i];
        v1SubV2.in[1][i] <== v2bits2.out[i];
    }

    out <== v1SubV2.aux;
}

template CmpBits(n) {
    signal input in1[n];
    signal input in2[n];
    signal output out;

    var i;

    component v1SubV2 = BinSub(n);

    for(i=0; i < n; i++) {
        v1SubV2.in[0][i] <== in1[i];
        v1SubV2.in[1][i] <== in2[i];
    }

    out <== v1SubV2.aux;
}
