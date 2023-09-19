// This file is the identity management contract.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;
pragma abicoder v2;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract IdentityManager is AccessControl {
    struct BabyPoint {
        uint256 x;
        uint256 y;
    }

    struct IdentityMeta {
        uint256 A;
        uint256 C2;
        // ei(64) | Ys(1) | Ais(1) | C3s(1) | C2s(1) | C1s(1)
        uint256 ei;
    }

    struct IdentityFullMeta {
        uint256 A;
        uint256 C1;
        uint256 C2;
        uint256 C3;
        // ei(64) | Ys(1) | Ais(1) | C3s(1) | C2s(1) | C1s(1)
        uint256 ei;
    }

    Verifier.VerifyingKey public deriveVK;
    Verifier.VerifyingKey public appkeyVK;

    mapping(address => IdentityMeta) public identityInfo;
    mapping(uint256 => address) public identityAddress;

    // pendingRevokeRootNum[version][root1][root2] = number
    mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) public pendingRootsNum;
    // revokeRootApprovers[version][root1][root2][address] = 1|0
    mapping(uint256 => mapping(uint256 => mapping(uint256 => mapping(address => uint256)))) public rootsApprovers;

    uint256 public rootsHash1;
    uint256 public rootsHash2;
    uint256 public rootsVersion;

    mapping(uint256 => address) public committee;
    mapping(address => uint256) public committeeId;
    mapping(address => mapping(uint256 => uint256)) public appkeys;

    uint256 public numOfAddress;
    uint256 public numOfCommittee;
    uint256 public baseNumber;

    BabyPoint public tpkePub;
    


    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function setTpkePub(BabyPoint memory key) external onlyRole(DEFAULT_ADMIN_ROLE) {
        tpkePub = key;
    }

    function updateRootsHash(uint256 rh1, uint256 rh2, uint256 version) external {
        require(committeeId[msg.sender] != 0, "not in committee");
        require(rootsApprovers[version][rh1][rh2][msg.sender] == 0, "already approve");
        rootsApprovers[version][rh1][rh2][msg.sender] = 1;
        pendingRootsNum[version][rh1][rh2] += 1;
        if (pendingRootsNum[version][rh1][rh2] >= baseNumber && version >= rootsVersion) {
            rootsHash1 = rh1;
            rootsHash2 = rh2;
            rootsVersion = version;
        }
        emit rootsUpdate(version, rh1, rh2);
    }

    function setBaseNumber(uint256 num) external onlyRole(DEFAULT_ADMIN_ROLE) {
        baseNumber = num;
    }

    function addCommittee(uint256 _cm) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address cm = address(uint160(_cm));
        require(committeeId[cm] == 0, "already add");
        numOfCommittee += 1;
        committee[numOfCommittee] = cm;
        
        committeeId[cm] = numOfCommittee;
    }

    function removeCommittee(address cm) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(committeeId[cm] != 0, "not in committee");
        uint256 id = committeeId[cm];
        committee[id] = committee[numOfCommittee];
        committeeId[committee[numOfCommittee]] = id;
        committee[numOfCommittee] = address(0);
        numOfCommittee -= 1;
        committeeId[cm] = 0;
    }

    function setDeriveVK(Verifier.VerifyingKey memory vk) external onlyRole(DEFAULT_ADMIN_ROLE) {
        deriveVK.alfa1 = vk.alfa1;
        deriveVK.beta2 = vk.beta2;
        deriveVK.gamma2 = vk.gamma2;
        deriveVK.delta2 = vk.delta2;
        delete deriveVK.IC;
        for (uint i = 0; i < vk.IC.length; ++i) {
            deriveVK.IC.push(vk.IC[i]);
        }
    }

    function setAppkeyVK(Verifier.VerifyingKey memory vk) external onlyRole(DEFAULT_ADMIN_ROLE) {
        appkeyVK.alfa1 = vk.alfa1;
        appkeyVK.beta2 = vk.beta2;
        appkeyVK.gamma2 = vk.gamma2;
        appkeyVK.delta2 = vk.delta2;
        delete appkeyVK.IC;
        for (uint i = 0; i < vk.IC.length; ++i) {
            appkeyVK.IC.push(vk.IC[i]);
        }
    }

    function register(uint256[] memory input, Verifier.Proof memory proof) external {
        require(input.length == 6, "invalid input size");
        require((input[4] >> 69) <= numOfAddress, "invalid number");
        require(input[5] == rootsHash1 || input[5] == rootsHash2, "invalid root");
        uint256[] memory zkInput = new uint256[](7);
        
        for (uint i = 0; i < 6; i++)
            zkInput[i] = input[i];
        zkInput[6] = uint256(uint160(msg.sender));

        uint256 err = Verifier.verify(
            zkInput,
            proof,
            deriveVK
        );

        require(err == 0, "invalid proof");
        identityInfo[msg.sender] = IdentityMeta(input[3], input[1], (input[4] & 0x1fffffffffffffffff));
        emit UserRegister(msg.sender, IdentityFullMeta(input[3], input[0], input[1], input[2], (input[4] & 0x1fffffffffffffffff)));
        emit UserMarked(input[0], msg.sender);
    }

    function verifyAppkey(address user, uint256 appkey, uint256 appid, Verifier.Proof memory proof) external view returns (bool) {
        IdentityMeta memory meta = identityInfo[user]; 
        uint256[] memory zkInput = new uint256[](4);
        uint256 ss = (appid & 0x00ffffffffffffffffffffffffffffffffffffffff) + ((tpkePub.x & 1) << 160) + (((meta.ei >> 1) & 1) << 161);
        zkInput[0] = appkey;
        zkInput[1] = ss;
        zkInput[2] = tpkePub.y;
        zkInput[3] = meta.C2;

        if (Verifier.verify(zkInput, proof, appkeyVK) == 0) {
            return true;
        } else {
            return false;
        }
    }

    function setAppkey(uint256 user, uint256 appkey, uint256 appid, Verifier.Proof memory proof) external {
        IdentityMeta memory meta = identityInfo[address(uint160(user))]; 
        uint256[] memory zkInput = new uint256[](4);
        uint256 ss = (appid & 0x00ffffffffffffffffffffffffffffffffffffffff) + ((tpkePub.x & 1) << 160) + (((meta.ei >> 1) & 1) << 161);
        zkInput[0] = appkey;
        zkInput[1] = ss;
        zkInput[2] = tpkePub.y;
        zkInput[3] = meta.C2;

        require(Verifier.verify(zkInput, proof, appkeyVK) == 0, "Invalid Proof!");
        // appkeys[address(uint160(user))][appid] = appkey;
        emit AppkeySet(address(uint160(user)), appid, appkey);
    }

    function revoke(address[] memory addrs) external {
         require(committeeId[msg.sender] != 0, "not in committee");
         for (uint i = 0; i < addrs.length; ++i) {
             delete identityInfo[addrs[i]];
             emit AddressRevoke(addrs[i]);
         }
    }

    event AppkeySet(address indexed user, uint256 appid, uint256 appkey);
    event UserRegister(address indexed user, IdentityFullMeta meta);
    event UserMarked(uint256 indexed c1y, address user);
    event rootsUpdate(uint256 version, uint256 root1, uint256 root2);
    event AddressRevoke(address indexed user);
}


library Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }
    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verify(
        uint256[] memory input,
        Proof memory proof,
        VerifyingKey memory vk
    ) internal view returns (uint256) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        require(input.length + 1 == vk.IC.length, "verifier-bad-input");
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x =  vk.IC[0];
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field, "verifier-gte-snark-scalar-field");
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }
        // vk_x = Pairing.addition(vk_x,);
        if (
            !Pairing.pairingProd4(
                Pairing.negate(proof.A),
                proof.B,
                vk.alfa1,
                vk.beta2,
                vk_x,
                vk.gamma2,
                proof.C,
                vk.delta2
            )
        ) return 1;
        return 0;
    }

    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory input,
        VerifyingKey memory vk
    ) internal view returns (bool) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        if (verify(input, proof, vk) == 0) {
            return true;
        } else {
            return false;
        }
    }
}

library Pairing {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /// @return the generator of G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    /// @return the generator of G2
    function P2() internal pure returns (G2Point memory) {
        // Original code point
        return
            G2Point(
                [
                    11559732032986387107991004021392285783925812861821192530917403151452391805634,
                    10857046999023057135944570762232829481370756359578518086990519993285655852781
                ],
                [
                    4082367875863433681332203403145435568316851327593401208105741076214120093531,
                    8495653923123431417604973247489272438418190587263600148770280649306958101930
                ]
            );

        /*
        // Changed by Jordi point
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
*/
    }

    /// @return r the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory r) {
        // The prime q in the base field F_q for G1
            uint256 q
         = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2)
        internal
        view
        returns (G1Point memory r)
    {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
                case 0 {
                    invalid()
                }
        }
        require(success, "pairing-add-failed");
    }

    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint256 s)
        internal
        view
        returns (G1Point memory r)
    {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
                case 0 {
                    invalid()
                }
        }
        require(success, "pairing-mul-failed");
    }

    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        require(p1.length == p2.length, "pairing-lengths-failed");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint256[1] memory out;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                8,
                add(input, 0x20),
                mul(inputSize, 0x20),
                out,
                0x20
            )
            // Use "invalid" to make gas estimation work
            switch success
                case 0 {
                    invalid()
                }
        }
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }

    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}