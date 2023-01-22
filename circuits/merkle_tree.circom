pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/switcher.circom";
include "circomlib/bitify.circom";

template MerkleTree(n) {
    signal input path[n];
    signal input key;
    signal input value;
    signal output root;

    var i;

    component k2bits = Num2Bits(n);
    k2bits.in <== key;

    component hash[n];
    component switcher[n];

    switcher[0] = Switcher();
    switcher[0].L <== value;
    switcher[0].R <== path[0];

    switcher[0].sel <== k2bits.out[0];

    hash[0] = Poseidon(2);
    hash[0].inputs[0] <== switcher[0].outL;
    hash[0].inputs[1] <== switcher[0].outR;

    for (i=1; i<n; i++) {
        switcher[i] = Switcher();
        switcher[i].L <== hash[i-1].out;
        switcher[i].R <== path[i];

        switcher[i].sel <== k2bits.out[i];

        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== switcher[i].outL;
        hash[i].inputs[1] <== switcher[i].outR;
    }

    hash[n-1].out ==> root;
}

// component main {public [root]} = MerkleTree(63);