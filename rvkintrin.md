| Prototype                                                     | Mnemonic      | Short Description                         | Supported in                  |
| ------------------------------------------------------------- | ------------- | ----------------------------------------- | ----------------------------- |
| int32_t _rv32_aes32dsi(int32_t rs1, int32_t rs2, int bs);     | aes32dsi      | AES final round decryption / RV32.        | Zknd, Zkn, Zk (RV32)          |
| int32_t _rv32_aes32dsmi(int32_t rs1, int32_t rs2, int bs);    | aes32dsmi     | AES middle round decryption / RV32.       | Zknd, Zkn, Zk (RV32)          |
| int32_t _rv32_aes32esi(int32_t rs1, int32_t rs2, int bs);     | aes32esi      | AES final round encryption / RV32.        | Zkne, Zkn, Zk (RV32)          |
| int32_t _rv32_aes32esmi(int32_t rs1, int32_t rs2, int bs);    | aes32esmi     | AES middle round encryption / RV32.       | Zkne, Zkn, Zk (RV32)          |
| int64_t _rv64_aes64ds(int64_t rs1, int64_t rs2);              | aes64ds       | AES final round decryption / RV64.        | Zknd, Zkn, Zk (RV64)          |
| int64_t _rv64_aes64dsm(int64_t rs1, int64_t rs2);             | aes64dsm      | AES middle round decryption / RV64        | Zknd, Zkn, Zk (RV64)          |
| int64_t _rv64_aes64es(int64_t rs1, int64_t rs2);              | aes64es       | AES final round encryption / RV64.        | Zkne, Zkn, Zk (RV64)          |
| int64_t _rv64_aes64esm(int64_t rs1, int64_t rs2);             | aes64esm      | AES middle round encryption / RV64.       | Zkne, Zkn, Zk (RV64)          |
| int64_t _rv64_aes64im(int64_t rs1);                           | aes64im       | AES Inverse MixColumns, key schedule.     | Zknd, Zkn, Zk (RV64)          |
| int64_t _rv64_aes64ks1i(int64_t rs1, int rnum);               | aes64ks1i     | AES key schedule, round number.           | Zkne, Zknd, Zkn, Zk (RV64)    |
| int64_t _rv64_aes64ks2(int64_t rs1, int64_t rs2);             | aes64ks2      | AES key schedule, word mixing.            | Zkne, Zknd, Zkn, Zk (RV64)    |
| int32_t _rv32_brev8(int32_t rs1);                             | brev8         | Reverse order of bits within each byte.   | Zbkb (RV32)                   |
| int64_t _rv64_brev8(int64_t rs1);                             | brev8         | Reverse order of bits within each byte.   | Zbkb (RV64)                   |
| int32_t _rv32_clmul(int32_t rs1, int32_t rs2);                | clmul         | Carry-less multiply (low 32 bits).        | Zbc, Zbkc (RV32)              |
| int64_t _rv64_clmul(int64_t rs1, int64_t rs2);                | clmul         | Carry-less multiply (low 64 bits).        | Zbc, Zbkc (RV64)              |
| int64_t _rv64_clmulh(int64_t rs1, int64_t rs2);               | clmulh        | Carry-less multiply (high 32 bits).       | Zbc, Zbkc (RV32)              |
| int32_t _rv32_clmulh(int32_t rs1, int32_t rs2);               | clmulh        | Carry-less multiply (high 64 bits).       | Zbc, Zbkc (RV64)              |
| int32_t _rv32_rol(int32_t rs1, int32_t rs2);                  | rol[i][w]     | Circular left rotate of 32 bits.          | Zbb, Zbkb (RV32,RV64)         |
| int64_t _rv64_rol(int64_t rs1, int64_t rs2);                  | rol[i]        | Circular left rotate of 64 bits.          | Zbb, Zbkb (RV64)              |
| int32_t _rv32_ror(int32_t rs1, int32_t rs2);                  | ror[i][w]     | Circular right rotate of 32 bits.         | Zbb, Zbkb (RV32,RV64)         |
| int64_t _rv64_ror(int64_t rs1, int64_t rs2);                  | ror[i]        | Circular right rotate of 64 bits.         | Zbb, Zbkb (RV64)              |
| long _rv_sha256sig0(long rs1);                                | sha256sig0    | Sigma0 function for SHA2-256.             | Zknhv, Zknv, Zk (RV32,RV64)   |
| long _rv_sha256sig1(long rs1);                                | sha256sig1    | Sigma1 function for SHA2-256.             | Zknhv, Zknv, Zk (RV32,RV64)   |
| long _rv_sha256sum0(long rs1);                                | sha256sum0    | Sum0 function for SHA2-256.               | Zknhv, Zknv, Zk (RV32,RV64)   |
| long _rv_sha256sum1(long rs1);                                | sha256sum1    | Sum1 function for SHA2-256.               | Zknhv, Zknv, Zk (RV32,RV64)   |
| int32_t _rv32_sha512sig0h(int32_t rs1, int32_t rs2);          | sha512sig0h   | Sigma0 high half for SHA2-512.            | Zknhv, Zknv, Zk (RV32)        |
| int32_t _rv32_sha512sig0l(int32_t rs1, int32_t rs2);          | sha512sig0l   | Sigma0 low half for SHA2-512.             | Zknhv, Zknv, Zk (RV32)        |
| int32_t _rv32_sha512sig1h(int32_t rs1, int32_t rs2);          | sha512sig1h   | Sigma1 high half for SHA2-512.            | Zknhv, Zknv, Zk (RV32)        |
| int32_t _rv32_sha512sig1l(int32_t rs1, int32_t rs2);          | sha512sig1l   | Sigma1 low half for SHA2-512.             | Zknhv, Zknv, Zk (RV32)        |
| int32_t _rv32_sha512sum0r(int32_t rs1, int32_t rs2);          | sha512sum0r   | Sum0 function for SHA2-512.               | Zknhv, Zknv, Zk (RV32)        |
| int32_t _rv32_sha512sum1r(int32_t rs1, int32_t rs2);          | sha512sum1r   | Sum1 function for SHA2-512.               | Zknhv, Zknv, Zk (RV32)        |
| int64_t _rv64_sha512sig0(int64_t rs1);                        | sha512sig0    | Sigma0 function for SHA2-512.             | Zknhv, Zknv, Zk (RV64)        |
| int64_t _rv64_sha512sig1(int64_t rs1);                        | sha512sig1    | Sigma1 function for SHA2-512.             | Zknhv, Zknv, Zk (RV64)        |
| int64_t _rv64_sha512sum0(int64_t rs1);                        | sha512sum0    | Sum0 function for SHA2-512.               | Zknhv, Zknv, Zk (RV64)        |
| int64_t _rv64_sha512sum1(int64_t rs1);                        | sha512sum1    | Sum1 function for SHA2-512.               | Zknhv, Zknv, Zk (RV64)        |
| long _rv_sm3p0(long rs1);                                     | sm3p0         | P0 function for SM3 hash.                 | Zksh, Zks (RV32,RV64)         |
| long _rv_sm3p1(long rs1);                                     | sm3p1         | P1 function for SM3 hash.                 | Zksh, Zks (RV32,RV64)         |
| long _rv_sm4ed(int32_t rs1, int32_t rs2, int bs);             | sm4ed         | Accelerate SM4 cipher encrypt/decrypt.    | Zksed, Zks (RV32,RV64)        |
| long _rv_sm4ks(int32_t rs1, int32_t rs2, int bs);             | sm4ed         | Accelerate SM4 cipher key schedule.       | Zksed, Zks (RV32,RV64)        |
| int32_t _rv32_unzip(int32_t rs1);                             | unzip         | Odd/even bits into upper/lower halves.    | Zbkb (RV32)                   |
| int32_t _rv32_xperm4(int32_t rs1, int32_t rs2);               | xperm4        | Byte-wise lookup of indicies.             | Zbkx (RV32)                   |
| int64_t _rv64_xperm4(int64_t rs1, int64_t rs2);               | xperm4        | Byte-wise lookup of indicies.             | Zbkx (RV64)                   |
| int32_t _rv32_xperm8(int32_t rs1, int32_t rs2);               | xperm8        | Nibble-wise lookup of indicies.           | Zbkx (RV32)                   |
| int64_t _rv64_xperm8(int64_t rs1, int64_t rs2);               | xperm8        | Nibble-wise lookup of indicies.           | Zbkx (RV64)                   |
| int32_t _rv32_zip(int32_t rs1);                               | zip           | Upper/lower halves into odd/even bits.    | Zbkb (RV32)                   |
| ------------------------------------------------------------- | ------------- | ----------------------------------------- | ----------------------------- |

