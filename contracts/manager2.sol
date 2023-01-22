// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

import "hardhat/console.sol";

/**
 * @title Owner
 * @dev Set & change owner
 */
contract GasTest {

    address private owner;

    // event for EVM logging
    event TestFrom(address indexed oldOwner);

    struct Point {
        uint256 x;
        uint256 y;
    }

    struct Key {
        Point A;
        Point B;
    }

    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    struct VerifyingKey {
        G1Point alfa1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[8] IC;
    }

    struct Proof {
        G1Point A;
        G2Point B;
        G1Point C;
    }

    Proof zkProof;

    VerifyingKey deriveVK;

    Point P1;
    Key K1;
    uint256 x;
    uint256 y;

    /**
     * @dev Set contract deployer as owner
     */
    constructor() {
        P1 = Point(1, 2);
        K1.A = Point(1, 2);
        K1.B = Point(3, 4);

        zkProof.A = G1Point(1, 2);
        zkProof.B = G2Point([0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc, 0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9], [0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90, 0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e]);
        zkProof.C = G1Point(7, 8);

        deriveVK.alfa1 = G1Point(0x0000000000000000000000000000000000000000000000000000000000000001, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45);
        deriveVK.beta2 = G2Point([0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4, 0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7], [0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2, 0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc]);
        deriveVK.gamma2 = G2Point([uint256(17), 18], [uint256(19), 20]);
        deriveVK.delta2 = G2Point([uint256(21), 22], [uint256(23), 24]);
        // delete deriveVK.IC;
        for (uint i = 0; i < 8; ++i) {
            deriveVK.IC[i] = G1Point(30+i, 40+i);
        }



    }

    function testGas() external {
        for(uint256 i = 0; i < 6; ++i) {
            uint256[8] memory inputs;
            for(uint256 j = 0; j < 4; ++j) {
                inputs[j] = P1.x;
                inputs[j+4] = P1.y;
            }
        }

        emit TestFrom(msg.sender);
    }

    function testGas1() external {
        uint256[8] memory inputs;
        for(uint256 i = 0; i < 6; ++i) {
            for(uint256 j = 0; j < 8; ++j) {
                // inputs[j] = x;
                // inputs[j+4] = y;
            }
        }

        emit TestFrom(msg.sender);
    }

    function testGas2() external {
        // uint256[8] memory inputs;
        for(uint256 i = 0; i < 6; ++i) {
            for(uint256 j = 0; j < 8; ++j) {
                // inputs[j] = x;
                // inputs[j+4] = y;
            }
        }

        emit TestFrom(msg.sender);
    }

    function testGas3() external {
        uint256[8] memory inputs;
        // for(uint256 i = 0; i < 6; ++i) {
        //     for(uint256 j = 0; j < 8; ++j) {
        //         // inputs[j] = x;
        //         // inputs[j+4] = y;
        //     }
        // }

        emit TestFrom(msg.sender);
    }

    function testGas4() external {
        uint256[8] memory inputs;
        for(uint256 i = 0; i < 6; ++i) {
            for(uint256 j = 0; j < 8; ++j) {
                inputs[j] = x;
                // inputs[j+4] = y;
            }
        }

        emit TestFrom(msg.sender);
    }

    function testGas5() external {
        unchecked {
            uint256[24] memory inputs;
            for(uint256 i = 0; i < 24; ++i) {
                inputs[i] = x;
            }
        }

        emit TestFrom(msg.sender);
    }

    function testGas6() external {
        unchecked {
            uint256 x0 =x;
            uint256[] memory inputs = new uint256[](24);
            inputs[0] = x0;
            inputs[1] = x0;
            inputs[2] = x0;
            inputs[3] = x0;
            inputs[4] = x0;
            inputs[5] = x0;

            inputs[0] = x0;
            inputs[1] = x0;
            inputs[2] = x0;
            inputs[3] = x0;
            inputs[4] = x0;
            inputs[5] = x0;

            inputs[0] = x0;
            inputs[1] = x0;
            inputs[2] = x0;
            inputs[3] = x0;
            inputs[4] = x0;
            inputs[5] = x0;

            inputs[0] = x0;
            inputs[1] = x0;
            inputs[2] = x0;
            inputs[3] = x0;
            inputs[4] = x0;
            inputs[5] = x0;
        }

        emit TestFrom(msg.sender);
    }

    function testGas7() external {
        uint256 x0 = x;
        Point memory p = Point(0,0);
        assembly {
            let solidity_free_mem_ptr := mload(0x40)    
            mstore(solidity_free_mem_ptr, p)
            mstore(add(solidity_free_mem_ptr, 32), x0)
            mstore(add(solidity_free_mem_ptr, 64), x0)
            mstore(add(solidity_free_mem_ptr, 96), x0)
            mstore(add(solidity_free_mem_ptr, 128), x0)
            mstore(add(solidity_free_mem_ptr, 160), x0)
            mstore(add(solidity_free_mem_ptr, 192), x0)
            
            mstore(add(solidity_free_mem_ptr, 32), x0)
            mstore(add(solidity_free_mem_ptr, 64), x0)
            mstore(add(solidity_free_mem_ptr, 96), x0)
            mstore(add(solidity_free_mem_ptr, 128), x0)
            mstore(add(solidity_free_mem_ptr, 160), x0)
            mstore(add(solidity_free_mem_ptr, 192), x0)

            mstore(add(solidity_free_mem_ptr, 32), x0)
            mstore(add(solidity_free_mem_ptr, 64), x0)
            mstore(add(solidity_free_mem_ptr, 96), x0)
            mstore(add(solidity_free_mem_ptr, 128), x0)
            mstore(add(solidity_free_mem_ptr, 160), x0)
            mstore(add(solidity_free_mem_ptr, 192), x0)

            mstore(add(solidity_free_mem_ptr, 32), x0)
            mstore(add(solidity_free_mem_ptr, 64), x0)
            mstore(add(solidity_free_mem_ptr, 96), x0)
            mstore(add(solidity_free_mem_ptr, 128), x0)
            mstore(add(solidity_free_mem_ptr, 160), x0)
            mstore(add(solidity_free_mem_ptr, 192), x0)
        }

        emit TestFrom(msg.sender);
    }

    function testGas8() external returns (uint256 r) {
        assembly {
            let solidity_free_mem_ptr := mload(0x40)    
            mstore(solidity_free_mem_ptr, sload(add(K1.slot, 2)))
            r := mload(solidity_free_mem_ptr)
        }

        emit TestFrom(msg.sender);
    }

    function test9(uint256 i) external view returns (uint256 r) {
        Proof memory proof = zkProof;
        G1Point memory nA = G1Point(0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da, 0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6);
        uint256[4] memory addInput = [deriveVK.IC[0].X, deriveVK.IC[0].Y, 0, 0];
        uint256[1] memory out;

        G1Point[8] storage IC = deriveVK.IC;

        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let input_ptr := mload(0x40)
            let p := mload(proof)
            mstore(input_ptr, mload(nA))
            mstore(add(input_ptr, 32), mload(add(nA, 32)))
            mstore(add(input_ptr, 64), mload(add(p, 128)))
            mstore(add(input_ptr, 96), mload(add(p, 160)))
            mstore(add(input_ptr, 128), mload(add(p, 192)))
            mstore(add(input_ptr, 160), mload(add(p, 224)))

            mstore(add(input_ptr, 192), sload(deriveVK.slot))
            mstore(add(input_ptr, 224), sload(add(deriveVK.slot, 1)))
            mstore(add(input_ptr, 256), sload(add(deriveVK.slot, 2)))
            mstore(add(input_ptr, 288), sload(add(deriveVK.slot, 3)))
            mstore(add(input_ptr, 320), sload(add(deriveVK.slot, 4)))
            mstore(add(input_ptr, 352), sload(add(deriveVK.slot, 5)))

            mstore(add(input_ptr, 384), mload(addInput))
            mstore(add(input_ptr, 416), mload(add(addInput, 32)))
            mstore(add(input_ptr, 448), sload(add(deriveVK.slot, 6)))
            mstore(add(input_ptr, 480), sload(add(deriveVK.slot, 7)))
            mstore(add(input_ptr, 512), sload(add(deriveVK.slot, 8)))
            mstore(add(input_ptr, 544), sload(add(deriveVK.slot, 9)))

            mstore(add(input_ptr, 576), mload(add(p, 256)))
            mstore(add(input_ptr, 608), mload(add(p, 288)))
            mstore(add(input_ptr, 640), sload(add(deriveVK.slot, 10)))
            mstore(add(input_ptr, 672), sload(add(deriveVK.slot, 11)))
            mstore(add(input_ptr, 704), sload(add(deriveVK.slot, 12)))
            mstore(add(input_ptr, 736), sload(add(deriveVK.slot, 13)))

            mstore(add(input_ptr, 768), sload(add(IC.slot, 0)))
            mstore(add(input_ptr, 800), sload(add(IC.slot, 1)))
            mstore(add(input_ptr, 832), sload(add(IC.slot, 2)))
            mstore(add(input_ptr, 864), sload(add(IC.slot, 3)))
            mstore(add(input_ptr, 896), sload(add(IC.slot, 4)))

            r := mload(add(input_ptr, mul(i, 32)))

            // success := staticcall(
            //     sub(gas(), 2000),
            //     8,
            //     input_ptr,
            //     384,
            //     out,
            //     0x20
            // )
            // // Use "invalid" to make gas estimation work
            // switch success
            //     case 0 {
            //         invalid()
            //     }
        }

        // emit TestFrom(msg.sender);

        // r = out[0];
    }


    function test10(uint256 i) external view returns (uint256[3] memory mulInput) {
        uint256[] memory input = new uint256[](7);
        for(uint j = 0; j < 7; ++j) {
            input[j] = j + 10;
        }
        G1Point[8] storage IC = deriveVK.IC;
        assembly {
            mstore(mulInput, sload(add(IC.slot, shl(1, i))))
            mstore(add(mulInput, 32), sload(add(IC.slot, add(shl(1, i), 1))))
            mstore(add(mulInput, 64), mload(add(input, shl(5, i))))
        }
    }

    function test11(uint256 i) external view returns (uint256[3] memory mulInput) {
        uint256[] memory input = new uint256[](7);
        for(uint j = 0; j < 7; ++j) {
            input[j] = j + 10;
        }
        G1Point[8] memory IC;
        for (uint i = 0; i < 8; ++i) {
            IC[i] = G1Point(30+i, 40+i);
        }
        assembly {
            mstore(mulInput, mload(add(IC, shl(6, i))))
            mstore(add(mulInput, 32), mload(add(IC, add(shl(6, i), 32))))
            mstore(add(mulInput, 64), mload(add(input, shl(5, i))))
        }
    }

} 