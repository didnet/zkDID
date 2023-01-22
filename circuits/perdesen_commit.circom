pragma circom 2.0.0;

include "circomlib/babyjub.circom";
include "circomlib/escalarmulany.circom";
include "circomlib/binsub.circom";
include "circomlib/eddsaposeidon.circom";
include "merkle_tree.circom";
include "cmp.circom";
include "tpke_dual.circom";
include "check_point.circom";

template PedersenCommit() {
    // public input
    signal input Ax;
    signal input Ay;
    signal input l[10];
    signal input r[10];


    //private input
    // roots
    signal input k; 
    signal input a[10]; // CA

    var i;
    var j;
    var G[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    var Gi[10][2];
    Gi[0] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[1] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[3] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[4] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[5] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[6] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[7] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[8] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    Gi[9] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    component l2bits[10];
    component r2bits[10];
    component a2bits[10];
    component lcmp[10];
    component rcmp[10];

    for(i = 0; i < 10; i++) {
        l2bits[i] = Num2Bits(254);
        r2bits[i] = Num2Bits(254);
        a2bits[i] = Num2Bits(254);
        l2bits[i].in <== l[i];
        r2bits[i].in <== r[i];
        a2bits[i].in <== a[i];
        // check ei <= e
        lcmp[i] = CmpBits(254);
        rcmp[i] = CmpBits(254);
        for(j = 0; j < 254; j++) {
            lcmp[i].in1[j] <== a2bits[i].out[j];
            lcmp[i].in2[j] <== l2bits[i].out[j];
            //
            rcmp[i].in1[j] <== r2bits[i].out[j];
            rcmp[i].in2[j] <== a2bits[i].out[j];
        }
        lcmp[i].out === 1;
        rcmp[i].out === 1;
    }

    component k2bits = Num2Bits(254);
    k2bits.in <== k;

    component kG = EscalarMulFix(254, G);
    for (i=0; i<254; i++) {
        kG.e[i] <== k2bits.out[i];
    }
    
    component aG[10];
    aG[0] = EscalarMulFix(254, Gi[0]);
    for (i=0; i<254; i++) {
        aG[0].e[i] <== a2bits[0].out[i];
    }

    aG[1] = EscalarMulFix(254, Gi[1]);
    for (i=0; i<254; i++) {
        aG[1].e[i] <== a2bits[1].out[i];
    }

    aG[2] = EscalarMulFix(254, Gi[2]);
    for (i=0; i<254; i++) {
        aG[2].e[i] <== a2bits[2].out[i];
    }

    aG[3] = EscalarMulFix(254, Gi[3]);
    for (i=0; i<254; i++) {
        aG[3].e[i] <== a2bits[3].out[i];
    }

    aG[4] = EscalarMulFix(254, Gi[4]);
    for (i=0; i<254; i++) {
        aG[4].e[i] <== a2bits[4].out[i];
    }

    aG[5] = EscalarMulFix(254, Gi[5]);
    for (i=0; i<254; i++) {
        aG[5].e[i] <== a2bits[5].out[i];
    }

    aG[6] = EscalarMulFix(254, Gi[6]);
    for (i=0; i<254; i++) {
        aG[6].e[i] <== a2bits[6].out[i];
    }

    aG[7] = EscalarMulFix(254, Gi[7]);
    for (i=0; i<254; i++) {
        aG[7].e[i] <== a2bits[7].out[i];
    }
    aG[8] = EscalarMulFix(254, Gi[8]);
    for (i=0; i<254; i++) {
        aG[8].e[i] <== a2bits[8].out[i];
    }
    aG[9] = EscalarMulFix(254, Gi[9]);
    for (i=0; i<254; i++) {
        aG[9].e[i] <== a2bits[9].out[i];
    }

    // for(i = 1; i < 10; i++) {
    //     aG[i] = EscalarMulFix(254, Gi[i]);
    //     for (j=0; i<254; j++) {
    //         aG[i].e[j] <== a2bits[i].out[j];
    //     }
    // }

    component addA[10];

    

    addA[0] = BabyAdd();
    addA[0].x1 <== kG.out[0];
    addA[0].y1 <== kG.out[1];
    addA[0].x2 <== aG[0].out[0];
    addA[0].y2 <== aG[0].out[1];

    for(i = 1; i < 10; i++) {
        addA[i] = BabyAdd();
        addA[i].x1 <== addA[i-1].xout;
        addA[i].y1 <== addA[i-1].yout;
        addA[i].x2 <== aG[i].out[0];
        addA[i].y2 <== aG[i].out[1];
    }

    Ax === addA[9].xout;
    Ay === addA[9].yout;
}

component main {public [Ax, Ay, l, r] } = PedersenCommit();

