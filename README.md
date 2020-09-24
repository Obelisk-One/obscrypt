## go package详情
___

提供目前区块链技术中使用的椭圆曲线算法与哈希算法。
目前支持的算法包括：
```
        公钥计算算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： curve25519、ed25519、x25519
        签名算法：    
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： curve25519、ed25519、x25519
        验签算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： curve25519、ed25519、x25519
        加密算法：
                ECDSA类 ： sm2-std
        密钥协商算法：
                ECDSA类 ： sm2-std-DH、 sm2-std-ElGamal
        G点相乘算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： ed25519、x25519
        G点的乘加算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： ed25519
        点的压缩与解压缩算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
        从签名恢复公钥算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
        点的域转换算法：
                x25519-to-ed25519、ed25519-to-x25519
        哈希算法：
                sha1,sha256,double-sha256,sha512,sha3-256,sha3-512
                md4,md5,
                ripemd160
                blake256,blake512,blake2b,blake2s
                sm3,hash160
                keccak256,keccak512,keccak256-ripemd160

        HMAC算法：
                sha256,sha512,sm3
```