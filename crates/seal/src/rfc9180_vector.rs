//! RFC 9180 test vector, mode base, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM (kem 0x0020, kdf 0x0001,
//! aead 0x0002), the first encryption only. From the CFRG draft's `test-vectors.json`
//! (github.com/cfrg/draft-irtf-cfrg-hpke, master): proof that the suite this crate uses is the standard one, not only
//! self-consistent, and what the extension's WebCrypto implementation is checked against too.
pub const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
pub const IKM_R: &str = "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee";
pub const SK_RM: &str = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d";
pub const PK_RM: &str = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c";
pub const ENC: &str = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256";
pub const AAD: &str = "436f756e742d30";
pub const CT: &str = "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a";
pub const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
