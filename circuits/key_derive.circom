pragma circom 2.0.0;

include "circomlib/babyjub.circom";
include "circomlib/escalarmulany.circom";
include "circomlib/binsub.circom";
include "circomlib/eddsaposeidon.circom";
include "merkle_tree.circom";
include "cmp.circom";
include "tpke_dual.circom";
include "check_point.circom";

template KeyDerive(L1, L2) {
    // public input
    // cipher
    signal input C1y;
    signal input C2y;
    signal input C3y;

    // attributes
    signal input Aiy;
    // d =  n(64) | ei(64) | Ys(1) | Ais(1) | C3s(1) | C2s(1) | C1s(1)
    signal input dd;
    // rh = hash(rb, rc, Yy)
    signal input rh;
    // Derived key
    signal input addr;

    //private input
    // roots
    signal input rb; // blocked
    signal input rc; // CA
    // TPKE pubkey
    signal input Yy;

    signal input C1x;
    signal input C2x;
    signal input C3x;
    signal input Aix;
    signal input Yx;

    signal input Px; // CA's pubkey
    signal input Py;

    // signature
    signal input s;
    signal input R8x;
    signal input R8y;

    // sn = hash(b,nonce)
    signal input k;

    signal input x; // master key

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

    var i;
    var G[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    component dd2bits = Num2Bits(133);
    dd2bits.in <== dd;


    component C1Check = PointCheck();
    C1Check.s <== dd2bits.out[0];
    C1Check.x <== C1x;
    C1Check.y <== C1y;

    component C2Check = PointCheck();
    C2Check.s <== dd2bits.out[1];
    C2Check.x <== C2x;
    C2Check.y <== C2y;

    component C3Check = PointCheck();
    C3Check.s <== dd2bits.out[2];
    C3Check.x <== C3x;
    C3Check.y <== C3y;

    component AiCheck = PointCheck();
    AiCheck.s <== dd2bits.out[3];
    AiCheck.x <== Aix;
    AiCheck.y <== Aiy;

    component YCheck = PointCheck();
    YCheck.s <== dd2bits.out[4];
    YCheck.x <== Yx;
    YCheck.y <== Yy;

    // calculate X
    component x2bits = Num2Bits(254);
    x2bits.in <== x;

    component mulFixX = EscalarMulFix(254, G);
    for (i=0; i<254; i++) {
        mulFixX.e[i] <== x2bits.out[i];
    }

    // calculate B
    component b2bits = Num2Bits(254);
    b2bits.in <== b;

    component mulFixB = EscalarMulFix(254, G);
    for (i=0; i<254; i++) {
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
    
    // check Xy not in tree2
    component tree2 = MerkleTree(L2);
    for(i = 0; i < L2; i++) {
        tree2.path[i] <== path2[i];
    }
    tree2.key <== key2;
    tree2.value <== value2;
    tree2.root - rb === 0;

    component cmp1 = Cmp(254);
    cmp1.in1 <== mulFixX.out[1];
    cmp1.in2 <== value2;
    cmp1.out === 0;
    component cmp2 = Cmp(254);
    cmp2.in1 <== path2[0];
    cmp2.in2 <== mulFixX.out[1];
    cmp2.out === 0;

    // check ei <= e
    component cmp3 = CmpBits(64);
    component e2bits = Num2Bits(64);
    e2bits.in <== e;

    for(i = 0; i < 64; i++) {
        cmp3.in1[i] <== e2bits.out[i];
        cmp3.in2[i] <== dd2bits.out[i+5];
    }
    cmp3.out === 1;
    
    // check nonce <= n
    component cmp4 = CmpBits(64);
    component nonce2bits = Num2Bits(64);
    nonce2bits.in <== nonce;
    for(i = 0; i < 64; i++) {
        cmp4.in1[i] <== dd2bits.out[i+69];
        cmp4.in2[i] <== nonce2bits.out[i];
    }
    cmp4.out === 1;

    // check Ai = A + rG
    component r2bits = Num2Bits(254);
    r2bits.in <== r;

    component mulFixR = EscalarMulFix(254, G);
    for (i=0; i<254; i++) {
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
    component hash1 = Poseidon(4);
    hash1.inputs[0] <== mulFixX.out[0];
    hash1.inputs[1] <== mulFixX.out[1];
    hash1.inputs[2] <== mulFixB.out[0];
    hash1.inputs[3] <== mulFixB.out[1];

    component hash2 = Poseidon(4);
    hash2.inputs[0] <== hash1.out;
    hash2.inputs[1] <== Ax;
    hash2.inputs[2] <== Ay;
    hash2.inputs[3] <== e;

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
    tpke.M1x <== mulFixX.out[0];
    tpke.M1y <== mulFixX.out[1];
    tpke.M2x <== Px;
    tpke.M2y <== Py;
    tpke.PKx <== Yx;
    tpke.PKy <== Yy;
    tpke.nonce <== addr;

    tpke.C1x === C1x;
    tpke.C1y === C1y;
    tpke.C2x === C2x;
    tpke.C2y === C2y;
    tpke.C3x === C3x;
    tpke.C3y === C3y;

    // check k = H(b,i)
    component hash3 = Poseidon(2);
    hash3.inputs[0] <== b;
    hash3.inputs[1] <== nonce;

    hash3.out === k;

    // check rh = h(rc, rb, Yy)
    // check k = H(b,i)
    component hash4 = Poseidon(3);
    hash4.inputs[0] <== rb;
    hash4.inputs[1] <== rc;
    hash4.inputs[2] <== Yy;

    hash4.out === rh;
    
}

component main {public [addr, C1y, C2y, C3y, Aiy, dd, rh] } = KeyDerive(19, 31);

