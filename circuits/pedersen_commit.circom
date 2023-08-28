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
    signal input lrcm;

    //private input
    // seed
    signal input k; 
    signal input a[8]; // atributes
    signal input l[8];
    signal input r[8];

    var i;
    var j;
    var G[2] = [
        995203441582195749578291179787384436505546430278305826713579947235728471134,
        5472060717959818805561601436314318772137091100104008585924551046643952123905
    ];

    var Gi[8][2];
    Gi[0] = [
        3709233544655094114095305628899106162100264105945362915460700051817000217269,
        12768044360317194929467284938524341882186637443921606345792322228824155198882
    ];

    Gi[1] = [
        21114813577525946862493269576609299497532859799554272967322590212668120427567,
        20691355949215438973895378684185926060668323158547601266162805165283114603642
    ];

    Gi[2] = [
        17625328386777005926307709551248024747691659287965267137690207058530731101871,
        8126690508250741460006030187731943180058104680946803211224658532738519221944
    ];

    Gi[3] = [
        15800272061361453462652215320637269033269242924073537434705176300283727080247,
        11210986719567668438700578192231096434213495698820271961498463217150294241773
    ];

    Gi[4] = [
        1076918765380774143164642194428017826965896759846395500273710191250140564695,
        6277032803431125082521875329448606153588193729080308891407659126278407332794
    ];

    Gi[5] = [
        10083117203619913772511200911994368415824947324922194844889644451106546262377,
        9406821708785457768010486607710887494561706835413712896651723470895041767510
    ];

    Gi[6] = [
        19476208024240268757551070309056276642802163789212938542233843238422269788927,
        13260462060444046883858963737081405245536577417134462088090858956361601270372
    ];

    Gi[7] = [
        11562500462764162036644261303661207031909061010885382076968723100699068566818,
        10943495341978773641186598690310331845231994940074104220132740812456397912788
    ];

    component l2bits[8];
    component r2bits[8];
    component a2bits[8];
    component lcmp[8];
    component rcmp[8];

    for(i = 0; i < 8; i++) {
        l2bits[i] = Num2Bits(254);
        r2bits[i] = Num2Bits(254);
        a2bits[i] = Num2Bits(254);
        l2bits[i].in <== l[i];
        r2bits[i].in <== r[i];
        a2bits[i].in <== a[i];
        lcmp[i] = CmpBits(230);
        rcmp[i] = CmpBits(230);
        for(j = 0; j < 230; j++) {
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
    
    component aG[8];
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

    // for(i = 1; i < 10; i++) {
    //     aG[i] = EscalarMulFix(254, Gi[i]);
    //     for (j=0; i<254; j++) {
    //         aG[i].e[j] <== a2bits[i].out[j];
    //     }
    // }

    component addA[8];

    addA[0] = BabyAdd();
    addA[0].x1 <== kG.out[0];
    addA[0].y1 <== kG.out[1];
    addA[0].x2 <== aG[0].out[0];
    addA[0].y2 <== aG[0].out[1];

    for(i = 1; i < 8; i++) {
        addA[i] = BabyAdd();
        addA[i].x1 <== addA[i-1].xout;
        addA[i].y1 <== addA[i-1].yout;
        addA[i].x2 <== aG[i].out[0];
        addA[i].y2 <== aG[i].out[1];
    }

    Ax === addA[7].xout;
    Ay === addA[7].yout;

    component hash1 = Poseidon(6);
    hash1.inputs[0] <== l[0];
    hash1.inputs[1] <== l[1];
    hash1.inputs[2] <== l[2];
    hash1.inputs[3] <== l[3];
    hash1.inputs[4] <== l[4];
    hash1.inputs[5] <== l[5];
    component hash2 = Poseidon(6);
    hash2.inputs[0] <== r[0];
    hash2.inputs[1] <== r[1];
    hash2.inputs[2] <== r[2];
    hash2.inputs[3] <== r[3];
    hash2.inputs[4] <== r[4];
    hash2.inputs[5] <== r[5];
    component hash3 = Poseidon(6);
    hash3.inputs[0] <== l[6];
    hash3.inputs[1] <== l[7];
    hash3.inputs[2] <== r[6];
    hash3.inputs[3] <== r[7];
    hash3.inputs[4] <== hash1.out;
    hash3.inputs[5] <== hash2.out;

    hash3.out === lrcm;
}

component main {public [Ax, Ay, lrcm] } = PedersenCommit();

