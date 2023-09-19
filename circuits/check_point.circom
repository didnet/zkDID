// check if (x,y) is a valid point on babyjub

pragma circom 2.0.0;
include "circomlib/babyjub.circom";

template PointCheck() {
    signal input s;
    signal input x;
    signal input y;

    component x2bits = Num2Bits(254);
    x2bits.in <== x;
    x2bits.out[0] === s;

    component check = BabyCheck();
    check.x <== x;
    check.y <== y;
}

// component main = PointCheck();