// This file is the gas-optimized version of the identity management contract.

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;
pragma abicoder v2;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract IdentityManager is AccessControl {
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

    struct VerifyingKey {
        G1Point alfa1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[] IC;
    }

    struct VerifyingKey8 {
        G1Point alfa1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[8] IC;
    }

    struct VerifyingKey5 {
        G1Point alfa1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[5] IC;
    }

    struct Proof {
        G1Point A;
        G2Point B;
        G1Point C;
    }

    function verify(
        uint256[] memory input,
        Proof memory proof,
        VerifyingKey5 memory vk
    ) internal view returns (uint256) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        require(input.length + 1 == 5, "verifier-bad-input");
        // Compute the linear combination vk_x
        G1Point memory vk_x =  vk.IC[0];
        for (uint256 i = 0; i < 4; i++) {
            require(input[i] < snark_scalar_field, "verifier-gte-snark-scalar-field");
            vk_x = addition(vk_x, scalar_mul(vk.IC[i + 1], input[i]));
        }
        // vk_x = addition(vk_x,);
        if (
            !pairingProd4(
                negate(proof.A),
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
        VerifyingKey5 memory vk
    ) internal view returns (bool) {
        Proof memory proof;
        proof.A = G1Point(a[0], a[1]);
        proof.B = G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = G1Point(c[0], c[1]);
        if (verify(input, proof, vk) == 0) {
            return true;
        } else {
            return false;
        }
    }

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

    VerifyingKey8 public deriveVK;
    VerifyingKey5 public appkeyVK;

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
    
    // Configure the public key used in threshold public key encryption.
    function setTpkePub(BabyPoint memory key) external onlyRole(DEFAULT_ADMIN_ROLE) {
        tpkePub = key;
    }
    
    // update root
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
    
    // set the threshold
    function setBaseNumber(uint256 num) external onlyRole(DEFAULT_ADMIN_ROLE) {
        baseNumber = num;
    }
    
    // add committee member
    function addCommittee(uint256 _cm) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address cm = address(uint160(_cm));
        require(committeeId[cm] == 0, "already add");
        numOfCommittee += 1;
        committee[numOfCommittee] = cm;
        
        committeeId[cm] = numOfCommittee;
    }
    
    // remove committee member
    function removeCommittee(address cm) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(committeeId[cm] != 0, "not in committee");
        uint256 id = committeeId[cm];
        committee[id] = committee[numOfCommittee];
        committeeId[committee[numOfCommittee]] = id;
        committee[numOfCommittee] = address(0);
        numOfCommittee -= 1;
        committeeId[cm] = 0;
    }
    
    // set verification key used in pseudonym verification
    function setDeriveVK(VerifyingKey memory vk) external onlyRole(DEFAULT_ADMIN_ROLE) {
        deriveVK.alfa1 = vk.alfa1;
        deriveVK.beta2 = vk.beta2;
        deriveVK.gamma2 = vk.gamma2;
        deriveVK.delta2 = vk.delta2;

        for (uint i = 0; i < vk.IC.length; ++i) {
            deriveVK.IC[i] = vk.IC[i];
        }
    }

    // set verification key used in sybil-resistance
    function setAppkeyVK(VerifyingKey memory vk) external onlyRole(DEFAULT_ADMIN_ROLE) {
        appkeyVK.alfa1 = vk.alfa1;
        appkeyVK.beta2 = vk.beta2;
        appkeyVK.gamma2 = vk.gamma2;
        appkeyVK.delta2 = vk.delta2;
        for (uint i = 0; i < vk.IC.length; ++i) {
            appkeyVK.IC[i] = vk.IC[i];
        }
    }
    
    // register a pseudonym
    function register(uint256[6] memory input, Proof memory proof) external {
        unchecked {
            require(input.length == 6, "invalid input size");
            require((input[4] >> 69) <= numOfAddress, "invalid number");
            require(input[5] == rootsHash1 || input[5] == rootsHash2, "invalid root");

            bool success;
            uint256[23] memory ic = [5134660633593042833528719061393118200934776146823219850066318084226671004521, 
                                    2267952479917080285641444598180230780028944522963408537447562438374065926314,
                                    16407509247147829170196141982734887097229943562806400832080443077548094155758,
                                    21596473358960641493638972487083159603153525942204706963721273625984982264259,
                                    input[0],
                                    6925175765785236950432228413894149495433938267345794109161445000316813397019,
                                    9978092574929667375508427641215895800063704027577168759932197805619175578922,
                                    input[1],
                                    11962465937233845977929587248665436890011299511766842400356310965882084745369,
                                    11852795729143130906245893142164683297154503493128266529386606845786002795090,
                                    input[2],
                                    7923608251787970531204788411020658796659787904994396956991822523952612974164,
                                    18530733978805246092347566020785953317755478010272555080991234289771805922217,
                                    input[3],
                                    5789407266548303026993138575911294527436021624687210030222316410853233583004,
                                    19461761860828311688721409768021034472165726286827528692572295578999643941121,
                                    input[4],
                                    113420956973449116039189466045708416412636738422786822404691558193761880485,
                                    10931001532875784697790335823017150997085694863324556575508636835092439518676,
                                    input[5],
                                    19213230504260099809941390966646840619093245128690369913102821461920973005336,
                                    15043819801595154591063362955695378087285118325664561591513210509122893701695,
                                    uint256(uint160(msg.sender))];

            uint256[4] memory addInput = [ic[0], ic[1], 0, 0];
            
            for (uint256 i = 2; i < 23; i += 3) {
                // solium-disable-next-line security/no-inline-assembly
                assembly {
                    // mul
                    success := staticcall(sub(gas(), 2000), 7, add(ic, shl(5, i)), 0x80, add(addInput, 64), 0x60)
                    // Use "invalid" to make gas estimation work
                    switch success
                        case 0 {
                            invalid()
                        }
                    // add
                    success := staticcall(sub(gas(), 2000), 6, addInput, 0xc0, addInput, 0x60)
                    // Use "invalid" to make gas estimation work
                    switch success
                        case 0 {
                            invalid()
                        }
                }
            }

            G1Point memory nA = negate(proof.A);

            uint256[1] memory out;
            // verify proof
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

                mstore(add(input_ptr, 192), 15004680706511599626910328362966724055512206210679380669568875056581533717585)
                mstore(add(input_ptr, 224), 12793303693169677763646490080736798058449472703770947246638652750917306945672)
                mstore(add(input_ptr, 256), 13097065549454820534121743293232923520157567628377343002556327061631672698839)
                mstore(add(input_ptr, 288), 16895363494149120493723056270615717759070118594067567018265725986466550985361)
                mstore(add(input_ptr, 320), 16486531148173516340100091740479150866101900379431723930312369778071641638548)
                mstore(add(input_ptr, 352), 17511194961672245380296015188312502808479795239469992960128839962609136281142)

                mstore(add(input_ptr, 384), mload(addInput))
                mstore(add(input_ptr, 416), mload(add(addInput, 32)))
                mstore(add(input_ptr, 448), 14777375175169188157832131510591300470451954576366387619180996124618844908687)
                mstore(add(input_ptr, 480), 11981441507299507102470311465607116257748363010408937132648026575661830000097)
                mstore(add(input_ptr, 512), 8355834854554503153303977692833755282736122888963222431148819254910459580129)
                mstore(add(input_ptr, 544), 14374981404404253893489930945664891321128987089025408333474411970725811850577)

                mstore(add(input_ptr, 576), mload(add(p, 256)))
                mstore(add(input_ptr, 608), mload(add(p, 288)))
                mstore(add(input_ptr, 640), 16205141538991564918569756141729310008779425547092684699822198443287220923422)
                mstore(add(input_ptr, 672), 14999972388366711006205615781095694617429565602724419962838787097035899700495)
                mstore(add(input_ptr, 704), 17269859523655542065343367422616573200895913101393606225638100595793707828721)
                mstore(add(input_ptr, 736), 13138917696645637545721069837184928280359742958705300500475876763920128987116)

                success := staticcall(
                    sub(gas(), 2000),
                    8,
                    input_ptr,
                    768,
                    out,
                    0x20
                )
                // Use "invalid" to make gas estimation work
                switch success
                    case 0 {
                        invalid()
                    }
            }

            require(out[0] != 0, "invalid proof");
            numOfAddress += 1;
            identityInfo[msg.sender] = IdentityMeta(input[3], input[1], (input[4] & 0x1fffffffffffffffff));
            emit UserRegister(msg.sender, IdentityFullMeta(input[3], input[0], input[1], input[2], (input[4] & 0x1fffffffffffffffff)));
            emit UserMarked(input[0], msg.sender);
        }
    }
    
    // verif non-sybil proof
    function _verifyAppkey(address user, uint256 appkey, uint256 appid, Proof memory proof) private view returns (bool) {
        unchecked {
            IdentityMeta memory meta = identityInfo[user]; 
            
            uint256 ss = (appid & 0x00ffffffffffffffffffffffffffffffffffffffff) + ((tpkePub.x & 1) << 160) + (((meta.ei >> 1) & 1) << 161);

            bool success;
            uint256[14] memory ic = [8681695336520126535119556549165341721423351312473992662099525921787530151585, 
                                    12374319359237741558473010548892797514389872488972723436464920039814544356679,
                                    13379349358787856777102530992872225424183700471726396385047031145537253120618,
                                    18452089298715675211781302447207012819430427580814844745351214037454502820170,
                                    appkey,
                                    11326354145213689504308823610299014028168702771822166239178222991067410244321,
                                    20740843430536100519679230788138585400402030838247720549740404770691261555584,
                                    ss,
                                    3066323588738464520825717934203092400801812635638664141868679461516145223478,
                                    3946948058574856131005170333627780776887033056551063128086399291198465356590,
                                    tpkePub.y,
                                    10609616205342156538225677282455559079476313795998787927728371992524810519801,
                                    4328252514927666684694372614903554151348173166365361362379403845001882363198,
                                    meta.C2];
 
            uint256[4] memory addInput = [ic[0], ic[1], 0, 0];

            for (uint256 i = 2; i < 14; i += 3) {
                // solium-disable-next-line security/no-inline-assembly
                assembly {
                    // mul
                    success := staticcall(sub(gas(), 2000), 7, add(ic, shl(5, i)), 0x80, add(addInput, 64), 0x60)
                    // Use "invalid" to make gas estimation work
                    switch success
                        case 0 {
                            invalid()
                        }
                    // add
                    success := staticcall(sub(gas(), 2000), 6, addInput, 0xc0, addInput, 0x60)
                    // Use "invalid" to make gas estimation work
                    switch success
                        case 0 {
                            invalid()
                        }
                }
            }

            G1Point memory nA = negate(proof.A);

            uint256[1] memory out;
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

                mstore(add(input_ptr, 192), 5206401496556851562670317152043658774341610659687039266022786915302561785775)
                mstore(add(input_ptr, 224), 14024044104912601359321570025531668481012700754598402622596027436436951186030)
                mstore(add(input_ptr, 256), 11587614424353515804126452619658501018799388867535989391657967304749651242094)
                mstore(add(input_ptr, 288), 2278142985214772475755058964612504654991486960695249856499852466767482771700)
                mstore(add(input_ptr, 320), 16423960841969181958300717999987700214876903485299997238946390133587982964526)
                mstore(add(input_ptr, 352), 4194947490766889838262625241935850584032639549994838290238071714738619085191)

                mstore(add(input_ptr, 384), mload(addInput))
                mstore(add(input_ptr, 416), mload(add(addInput, 32)))
                mstore(add(input_ptr, 448), 4422351400425110778272910363335403758636324961559845492787788451679573469610)
                mstore(add(input_ptr, 480), 9262006424273923686784441527336999112784359539970941821252718359588993024577)
                mstore(add(input_ptr, 512), 15316414987326097708688648720229009223342872797323168774985472769536620323853)
                mstore(add(input_ptr, 544), 14808066007352459609647288910650046740826146516946968899415447127415389166479)

                mstore(add(input_ptr, 576), mload(add(p, 256)))
                mstore(add(input_ptr, 608), mload(add(p, 288)))
                mstore(add(input_ptr, 640), 10852659904564012410202905745144849052505185111242142102989755104597444077299)
                mstore(add(input_ptr, 672), 20914531760414482914325177373272580492176957530777621907979367234316410095242)
                mstore(add(input_ptr, 704), 2326776246568318616235239342488121144967415672643713588789909725633667289456)
                mstore(add(input_ptr, 736), 15672502731658008787285140340453255737078324222641564237988234198627619400790)

                success := staticcall(
                    sub(gas(), 2000),
                    8,
                    input_ptr,
                    768,
                    out,
                    0x20
                )
                // Use "invalid" to make gas estimation work
                switch success
                    case 0 {
                        invalid()
                    }
            }

            return out[0] != 0;
        }
    }
    
    // verify identity proof
    function _verifyIdentity(uint256 Ax, uint256 Ay, uint256 lrcm, Proof memory proof) private view returns (bool) {
        unchecked {
            bool success;
            uint256[11] memory ic = [21608667410711496812882370846235082219809050337084794157590759186282637585344, 
                                    8384970959349601680244718450283120484320605195854625117378385026013772292021,
                                    12930562548973283330975689962732440629491891663905338974653083221514519265377,
                                    8541024393053639618711371261917675935279102263704358351483488059897820955759,
                                    Ax,
                                    10609360200435912527995129309664390933531648009707591003577368789200152017717,
                                    14180162505845651140956990310649386789331886882569317105763202670045449480192,
                                    Ay,
                                    16062641557297711677740458410901445049075987379407037317083259568574001699538,
                                    11777838497844809403393627126455609270770258213121070946946596242813847185727,
                                    lrcm];
 
            uint256[4] memory addInput = [ic[0], ic[1], 0, 0];

            for (uint256 i = 2; i < 11; i += 3) {
                // solium-disable-next-line security/no-inline-assembly
                assembly {
                    // mul
                    success := staticcall(sub(gas(), 2000), 7, add(ic, shl(5, i)), 0x80, add(addInput, 64), 0x60)
                    // Use "invalid" to make gas estimation work
                    switch success
                        case 0 {
                            invalid()
                        }
                    // add
                    success := staticcall(sub(gas(), 2000), 6, addInput, 0xc0, addInput, 0x60)
                    // Use "invalid" to make gas estimation work
                    switch success
                        case 0 {
                            invalid()
                        }
                }
            }

            G1Point memory nA = negate(proof.A);

            uint256[1] memory out;
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

                mstore(add(input_ptr, 192), 12384001975923688725549742349895603667455215160914868304700754701164505642909)
                mstore(add(input_ptr, 224), 5975026680599206326232695526971437334542177145566564851398527296992076315415)
                mstore(add(input_ptr, 256), 13944611227234014573879338971726596196482551298890971838068705721028877203212)
                mstore(add(input_ptr, 288), 4409934194387708543469033564486655569509854572986772143714411625202809918632)
                mstore(add(input_ptr, 320), 11527400980324097681578115660111103028502187793758840400974727595583940835735)
                mstore(add(input_ptr, 352), 14351083625812150963808759664503111953747850513047595535267643152793025353683)

                mstore(add(input_ptr, 384), mload(addInput))
                mstore(add(input_ptr, 416), mload(add(addInput, 32)))
                mstore(add(input_ptr, 448), 11941059669465163061853561469820256147437355156173567052685494753916367262469)
                mstore(add(input_ptr, 480), 16035318089773333271556401822323971304811351096893027030165750226014290706105)
                mstore(add(input_ptr, 512), 18387868787256835186818573036147744300492166721630369292388153019641797323074)
                mstore(add(input_ptr, 544), 14073326839883679256308089936028750274974042315401580191367769290002278472958)

                mstore(add(input_ptr, 576), mload(add(p, 256)))
                mstore(add(input_ptr, 608), mload(add(p, 288)))
                mstore(add(input_ptr, 640), 19708058406394478327149338044055579191693306402236207449279510091971281200620)
                mstore(add(input_ptr, 672), 5240669643643026443632390885206189492435129263715881989848944311893357519426)
                mstore(add(input_ptr, 704), 19413083123968390435388334866014389827628549280403785341773303949986021491035)
                mstore(add(input_ptr, 736), 3808730047386445717105598783484442401127247732841039383203424346271425442004)

                success := staticcall(
                    sub(gas(), 2000),
                    8,
                    input_ptr,
                    768,
                    out,
                    0x20
                )
                // Use "invalid" to make gas estimation work
                switch success
                    case 0 {
                        invalid()
                    }
            }

            return out[0] != 0;
        }
    }
    
    // Verify the identity assertion.
    function verifyIdentity(uint256 Ax, uint256 Ay, uint256 lrcm, Proof memory proof) external {
        require(_verifyIdentity(Ax, Ay, lrcm, proof), "Invalid Proof!");
        emit IdentityVerified(Ax, Ay, lrcm);
    }
    
    // verify non-sybil proof
    function verifyAppkey(address user, uint256 appkey, uint256 appid, Proof memory proof) external view returns (bool) {
        return _verifyAppkey(user, appkey, appid, proof);
    }
    
    // do sybil-resistance
    function setAppkey(uint256 user, uint256 appkey, uint256 appid, Proof memory proof) external {
        unchecked {
            require(_verifyAppkey(address(uint160(user)), appkey, appid, proof), "Invalid Proof!");
            // appkeys[address(uint160(user))][appid] = appkey;
            emit AppkeySet(address(uint160(user)), appid, appkey);
        }
    }
    
    // revoke pseudonyms
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
    event IdentityVerified(uint256 indexed Ax, uint256 indexed Ay, uint256 lrcm);
}
