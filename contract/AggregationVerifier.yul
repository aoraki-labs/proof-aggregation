
        object "plonk_verifier" {
            code {
                function allocate(size) -> ptr {
                    ptr := mload(0x40)
                    if eq(ptr, 0) { ptr := 0x60 }
                    mstore(0x40, add(ptr, size))
                }
                let size := datasize("Runtime")
                let offset := allocate(size)
                datacopy(offset, dataoffset("Runtime"), size)
                return(offset, size)
            }
            object "Runtime" {
                code {
                    let success:bool := true
                    let f_p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                    let f_q := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                    function validate_ec_point(x, y) -> valid:bool {
                        {
                            let x_lt_p:bool := lt(x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let y_lt_p:bool := lt(y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            valid := and(x_lt_p, y_lt_p)
                        }
                        {
                            let y_square := mulmod(y, y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let x_square := mulmod(x, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let x_cube := mulmod(x_square, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let x_cube_plus_3 := addmod(x_cube, 3, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                            let is_affine:bool := eq(x_cube_plus_3, y_square)
                            valid := and(valid, is_affine)
                        }
                    }
                    mstore(0x20, mod(calldataload(0x0), f_q))
mstore(0x40, mod(calldataload(0x20), f_q))
mstore(0x60, mod(calldataload(0x40), f_q))
mstore(0x80, mod(calldataload(0x60), f_q))
mstore(0xa0, mod(calldataload(0x80), f_q))
mstore(0xc0, mod(calldataload(0xa0), f_q))
mstore(0xe0, mod(calldataload(0xc0), f_q))
mstore(0x100, mod(calldataload(0xe0), f_q))
mstore(0x120, mod(calldataload(0x100), f_q))
mstore(0x140, mod(calldataload(0x120), f_q))
mstore(0x160, mod(calldataload(0x140), f_q))
mstore(0x180, mod(calldataload(0x160), f_q))
mstore(0x1a0, mod(calldataload(0x180), f_q))
mstore(0x1c0, mod(calldataload(0x1a0), f_q))
mstore(0x1e0, mod(calldataload(0x1c0), f_q))
mstore(0x200, mod(calldataload(0x1e0), f_q))
mstore(0x0, 10320900538605064363781727641580778840857116830575312185784371189493771196316)

        {
            let x := calldataload(0x200)
            mstore(0x220, x)
            let y := calldataload(0x220)
            mstore(0x240, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x240)
            mstore(0x260, x)
            let y := calldataload(0x260)
            mstore(0x280, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x280)
            mstore(0x2a0, x)
            let y := calldataload(0x2a0)
            mstore(0x2c0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x2c0)
            mstore(0x2e0, x)
            let y := calldataload(0x2e0)
            mstore(0x300, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x300)
            mstore(0x320, x)
            let y := calldataload(0x320)
            mstore(0x340, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x360, keccak256(0x0, 864))
{
            let hash := mload(0x360)
            mstore(0x380, mod(hash, f_q))
            mstore(0x3a0, hash)
        }

        {
            let x := calldataload(0x340)
            mstore(0x3c0, x)
            let y := calldataload(0x360)
            mstore(0x3e0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x380)
            mstore(0x400, x)
            let y := calldataload(0x3a0)
            mstore(0x420, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x3c0)
            mstore(0x440, x)
            let y := calldataload(0x3e0)
            mstore(0x460, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x400)
            mstore(0x480, x)
            let y := calldataload(0x420)
            mstore(0x4a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x440)
            mstore(0x4c0, x)
            let y := calldataload(0x460)
            mstore(0x4e0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x480)
            mstore(0x500, x)
            let y := calldataload(0x4a0)
            mstore(0x520, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x4c0)
            mstore(0x540, x)
            let y := calldataload(0x4e0)
            mstore(0x560, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x500)
            mstore(0x580, x)
            let y := calldataload(0x520)
            mstore(0x5a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x540)
            mstore(0x5c0, x)
            let y := calldataload(0x560)
            mstore(0x5e0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x580)
            mstore(0x600, x)
            let y := calldataload(0x5a0)
            mstore(0x620, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x640, keccak256(0x3a0, 672))
{
            let hash := mload(0x640)
            mstore(0x660, mod(hash, f_q))
            mstore(0x680, hash)
        }
mstore8(1696, 1)
mstore(0x6a0, keccak256(0x680, 33))
{
            let hash := mload(0x6a0)
            mstore(0x6c0, mod(hash, f_q))
            mstore(0x6e0, hash)
        }

        {
            let x := calldataload(0x5c0)
            mstore(0x700, x)
            let y := calldataload(0x5e0)
            mstore(0x720, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x600)
            mstore(0x740, x)
            let y := calldataload(0x620)
            mstore(0x760, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x640)
            mstore(0x780, x)
            let y := calldataload(0x660)
            mstore(0x7a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x680)
            mstore(0x7c0, x)
            let y := calldataload(0x6a0)
            mstore(0x7e0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x6c0)
            mstore(0x800, x)
            let y := calldataload(0x6e0)
            mstore(0x820, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x700)
            mstore(0x840, x)
            let y := calldataload(0x720)
            mstore(0x860, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x740)
            mstore(0x880, x)
            let y := calldataload(0x760)
            mstore(0x8a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x780)
            mstore(0x8c0, x)
            let y := calldataload(0x7a0)
            mstore(0x8e0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x900, keccak256(0x6e0, 544))
{
            let hash := mload(0x900)
            mstore(0x920, mod(hash, f_q))
            mstore(0x940, hash)
        }

        {
            let x := calldataload(0x7c0)
            mstore(0x960, x)
            let y := calldataload(0x7e0)
            mstore(0x980, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x800)
            mstore(0x9a0, x)
            let y := calldataload(0x820)
            mstore(0x9c0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x840)
            mstore(0x9e0, x)
            let y := calldataload(0x860)
            mstore(0xa00, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x880)
            mstore(0xa20, x)
            let y := calldataload(0x8a0)
            mstore(0xa40, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0xa60, keccak256(0x940, 288))
{
            let hash := mload(0xa60)
            mstore(0xa80, mod(hash, f_q))
            mstore(0xaa0, hash)
        }
mstore(0xac0, mod(calldataload(0x8c0), f_q))
mstore(0xae0, mod(calldataload(0x8e0), f_q))
mstore(0xb00, mod(calldataload(0x900), f_q))
mstore(0xb20, mod(calldataload(0x920), f_q))
mstore(0xb40, mod(calldataload(0x940), f_q))
mstore(0xb60, mod(calldataload(0x960), f_q))
mstore(0xb80, mod(calldataload(0x980), f_q))
mstore(0xba0, mod(calldataload(0x9a0), f_q))
mstore(0xbc0, mod(calldataload(0x9c0), f_q))
mstore(0xbe0, mod(calldataload(0x9e0), f_q))
mstore(0xc00, mod(calldataload(0xa00), f_q))
mstore(0xc20, mod(calldataload(0xa20), f_q))
mstore(0xc40, mod(calldataload(0xa40), f_q))
mstore(0xc60, mod(calldataload(0xa60), f_q))
mstore(0xc80, mod(calldataload(0xa80), f_q))
mstore(0xca0, mod(calldataload(0xaa0), f_q))
mstore(0xcc0, mod(calldataload(0xac0), f_q))
mstore(0xce0, mod(calldataload(0xae0), f_q))
mstore(0xd00, mod(calldataload(0xb00), f_q))
mstore(0xd20, mod(calldataload(0xb20), f_q))
mstore(0xd40, mod(calldataload(0xb40), f_q))
mstore(0xd60, mod(calldataload(0xb60), f_q))
mstore(0xd80, mod(calldataload(0xb80), f_q))
mstore(0xda0, mod(calldataload(0xba0), f_q))
mstore(0xdc0, mod(calldataload(0xbc0), f_q))
mstore(0xde0, mod(calldataload(0xbe0), f_q))
mstore(0xe00, mod(calldataload(0xc00), f_q))
mstore(0xe20, mod(calldataload(0xc20), f_q))
mstore(0xe40, mod(calldataload(0xc40), f_q))
mstore(0xe60, mod(calldataload(0xc60), f_q))
mstore(0xe80, mod(calldataload(0xc80), f_q))
mstore(0xea0, mod(calldataload(0xca0), f_q))
mstore(0xec0, mod(calldataload(0xcc0), f_q))
mstore(0xee0, mod(calldataload(0xce0), f_q))
mstore(0xf00, mod(calldataload(0xd00), f_q))
mstore(0xf20, mod(calldataload(0xd20), f_q))
mstore(0xf40, mod(calldataload(0xd40), f_q))
mstore(0xf60, mod(calldataload(0xd60), f_q))
mstore(0xf80, mod(calldataload(0xd80), f_q))
mstore(0xfa0, mod(calldataload(0xda0), f_q))
mstore(0xfc0, mod(calldataload(0xdc0), f_q))
mstore(0xfe0, mod(calldataload(0xde0), f_q))
mstore(0x1000, mod(calldataload(0xe00), f_q))
mstore(0x1020, mod(calldataload(0xe20), f_q))
mstore(0x1040, mod(calldataload(0xe40), f_q))
mstore(0x1060, mod(calldataload(0xe60), f_q))
mstore(0x1080, mod(calldataload(0xe80), f_q))
mstore(0x10a0, mod(calldataload(0xea0), f_q))
mstore(0x10c0, mod(calldataload(0xec0), f_q))
mstore(0x10e0, mod(calldataload(0xee0), f_q))
mstore(0x1100, mod(calldataload(0xf00), f_q))
mstore(0x1120, mod(calldataload(0xf20), f_q))
mstore(0x1140, mod(calldataload(0xf40), f_q))
mstore(0x1160, mod(calldataload(0xf60), f_q))
mstore(0x1180, mod(calldataload(0xf80), f_q))
mstore(0x11a0, mod(calldataload(0xfa0), f_q))
mstore(0x11c0, mod(calldataload(0xfc0), f_q))
mstore(0x11e0, keccak256(0xaa0, 1856))
{
            let hash := mload(0x11e0)
            mstore(0x1200, mod(hash, f_q))
            mstore(0x1220, hash)
        }

        {
            let x := calldataload(0xfe0)
            mstore(0x1240, x)
            let y := calldataload(0x1000)
            mstore(0x1260, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x1020)
            mstore(0x1280, x)
            let y := calldataload(0x1040)
            mstore(0x12a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x1060)
            mstore(0x12c0, x)
            let y := calldataload(0x1080)
            mstore(0x12e0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x10a0)
            mstore(0x1300, x)
            let y := calldataload(0x10c0)
            mstore(0x1320, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x1340, keccak256(0x1220, 288))
{
            let hash := mload(0x1340)
            mstore(0x1360, mod(hash, f_q))
            mstore(0x1380, hash)
        }
{
            let x := mload(0x20)
x := add(x, shl(68, mload(0x40)))
x := add(x, shl(136, mload(0x60)))
x := add(x, shl(204, mload(0x80)))
mstore(5024, x)
let y := mload(0xa0)
y := add(y, shl(68, mload(0xc0)))
y := add(y, shl(136, mload(0xe0)))
y := add(y, shl(204, mload(0x100)))
mstore(5056, y)

            success := and(validate_ec_point(x, y), success)
        }
{
            let x := mload(0x120)
x := add(x, shl(68, mload(0x140)))
x := add(x, shl(136, mload(0x160)))
x := add(x, shl(204, mload(0x180)))
mstore(5088, x)
let y := mload(0x1a0)
y := add(y, shl(68, mload(0x1c0)))
y := add(y, shl(136, mload(0x1e0)))
y := add(y, shl(204, mload(0x200)))
mstore(5120, y)

            success := and(validate_ec_point(x, y), success)
        }

            if not(success) { revert(0, 0) }
            return(0, 0)

                }
            }
        }