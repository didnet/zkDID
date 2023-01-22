pragma circom 2.0.0;

include "circomlib/babyjub.circom";
include "circomlib/escalarmulany.circom";
include "circomlib/binsub.circom";
include "circomlib/eddsaposeidon.circom";
include "merkle_tree.circom";
include "cmp.circom";
include "tpke_dual.circom";
include "ecdsa/ecdsa.circom";

template KeyDerive(L1, L2) {
    // public input
    // Derived key
    signal input Dx[4];
    signal input Dy[4];
    // cipher
    signal input C1x;
    signal input C1y;
    signal input C2x;
    signal input C2y;
    signal input C3x;
    signal input C3y;
    // attributes
    signal input Aix;
    signal input Aiy;
    signal input ei;
    // roots
    signal input rc; // CA
    signal input rb1; // blocked
    signal input rb2; // blocked
    // number of address
    signal input n;
    // TPKE pubkey
    signal input Yx;
    signal input Yy;

    //private input
    signal input Px; // CA's pubkey
    signal input Py;

    // signature
    signal input s;
    signal input R8x;
    signal input R8y;

    signal input k;

    signal input Mx[4]; // master key
    signal input My[4]; // master key
    // Hk = hash(b,nonce)
    signal input Hk[4];

    signal input e;
    signal input b; // key
    // attributes
    signal input Ax;
    signal input Ay;

    signal input nonce;
    signal input r;

    signal input path1[L1];
    signal input key1;
    signal input path2[L2];
    signal input key2;
    signal input value2;

    signal MxL <== Mx[0] + Mx[1] * (2**64);
    signal MxH <== Mx[2] + Mx[3] * (2**64);
    signal MyL <== My[0] + My[1] * (2**64);
    signal MyH <== My[2] + My[3] * (2**64);
    
    signal newkey;

    var i;
    var G[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    // calculate B
    component b2bits = Num2Bits(256);
    b2bits.in <== b;

    component mulFixB = EscalarMulFix(256, G);
    for (i=0; i<256; i++) {
        mulFixB.e[i] <== b2bits.out[i];
    }

    // check ca in tree1
    component tree1 = MerkleTree(L1);
    for(i = 0; i < L1; i++) {
        tree1.path[i] <== path1[i];
    }
    tree1.key <== key1;
    tree1.value <== Py;
    tree1.root === rc;
    
    // check By not in tree2
    component tree2 = MerkleTree(L2);
    for(i = 0; i < L2; i++) {
        tree2.path[i] <== path2[i];
    }
    tree2.key <== key2;
    tree2.value <== value2;
    (tree2.root - rb1) * (tree2.root - rb2) === 0;

    component cmp1 = Cmp(254);
    cmp1.in1 <== mulFixB.out[1];
    cmp1.in2 <== value2;
    cmp1.out === 0;
    component cmp2 = Cmp(254);
    cmp2.in1 <== path2[0];
    cmp2.in2 <== mulFixB.out[1];
    cmp2.out === 0;

    // check ei <= e
    component cmp3 = Cmp(64);
    cmp3.in1 <== e;
    cmp3.in2 <== ei;
    cmp3.out === 1;
    
    // check nonce <= n
    component cmp4 = Cmp(64);
    cmp4.in1 <== n;
    cmp4.in2 <== nonce;
    cmp4.out === 1;

    // check Ai = A + rG
    component r2bits = Num2Bits(256);
    r2bits.in <== r;

    component mulFixR = EscalarMulFix(256, G);
    for (i=0; i<256; i++) {
        mulFixR.e[i] <== r2bits.out[i];
    }

    component addA = BabyAdd();
    addA.x1 <== Ax;
    addA.y1 <== Ay;
    addA.x2 <== mulFixR.out[0];
    addA.y2 <== mulFixR.out[1];

    Aix === addA.xout;
    Aiy === addA.yout;

    // check sig
    component hash1 = Poseidon(5);
    hash1.inputs[0] <== MxL;
    hash1.inputs[1] <== MxH;
    hash1.inputs[2] <== MyL;
    hash1.inputs[3] <== MyH;
    hash1.inputs[4] <== mulFixB.out[0];

    component hash2 = Poseidon(5);
    hash2.inputs[0] <== hash1.out;
    hash2.inputs[1] <== mulFixB.out[1];
    hash2.inputs[2] <== Ax;
    hash2.inputs[3] <== Ay;
    hash2.inputs[4] <== e;

    component eddsa = EdDSAPoseidonVerifier();
    eddsa.enabled <== 1;
    eddsa.Ax <== Px;
    eddsa.Ay <== Py;
    eddsa.S <== s;
    eddsa.R8x <== R8x;
    eddsa.R8y <== R8y;
    eddsa.M <== hash2.out;
    
    //check cipher
    component tpke = TpkeEncryptionDual();
    tpke.k <== k;
    tpke.M1x <== mulFixB.out[0];
    tpke.M1y <== mulFixB.out[1];
    tpke.M2x <== Px;
    tpke.M2y <== Py;
    tpke.PKx <== Yx;
    tpke.PKy <== Yy;

    tpke.C1x === C1x;
    tpke.C1y === C1y;
    tpke.C2x === C2x;
    tpke.C2y === C2y;
    tpke.C3x === C3x;
    tpke.C3y === C3y;

    // check Xi = X + H(b,i)G
    component hash3 = Poseidon(2);
    hash3.inputs[0] <== b;
    hash3.inputs[1] <== nonce;

    hash3.out === (Hk[0] + Hk[1]*2**64 + Hk[2]*2**128 + Hk[3]*2**192);

    component h2G = ECDSAPrivToPub(64, 4);
    h2G.privkey[0] <== Hk[0];
    h2G.privkey[1] <== Hk[1];
    h2G.privkey[2] <== Hk[2];
    h2G.privkey[3] <== Hk[3];
    
    component mAddh = Secp256k1AddUnequal(64, 4);
    for(i = 0; i < 4; i++) {
        mAddh.a[0][i] <== Mx[i];
        mAddh.a[1][i] <== My[i];
        mAddh.b[0][i] <== h2G.pubkey[0][i];
        mAddh.b[1][i] <== h2G.pubkey[1][i]; 
    }

    for(i = 0; i < 4; i++) {
        Dx[i] === mAddh.out[0][i];
        Dy[i] === mAddh.out[1][i];
    }
    
}

component main = KeyDerive(20, 32);

