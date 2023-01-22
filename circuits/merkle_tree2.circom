pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/switcher.circom";
include "circomlib/bitify.circom";

template MerkleTree(n) {
    signal input path[2*n];
    signal input root;

    signal tmp[n];
    var i;

    component hash[n];
    component switcher[n];

    for (i=0; i<n-1; i++) {
        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== path[i];
        hash[i].inputs[1] <== path[i+n];
        tmp[i] <== (hash[i].out - path[i]) * (hash[i].out -path[i+n]);
        tmp[i] === 0;
    }

    hash[n-1] = Poseidon(2);
    hash[n-1].inputs[0] <== path[i];
    hash[n-1].inputs[1] <== path[i+n];

    hash[n-1].out === root;
}

component main {public [root]} = MerkleTree(63);