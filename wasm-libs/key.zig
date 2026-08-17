const std = @import("std");
const bi = @import("bigint.zig");

// -m^-1 mod 2^64 via Newton's iteration (doubles correct bits each step). The
// limb width is fixed, so this does not depend on the modulus size.
pub fn negInv64(m0: u64) u64 {
    var x: u64 = 1;
    inline for (0..6) |_| x = x *% (2 -% m0 *% x);
    return 0 -% x;
}

// An RSA CRT signing key for an N-limb prime (modulus = 2*N limbs). The limbs and
// Montgomery constants are produced at runtime from hex: everything here is
// computed once, before the benchmark's timing loop, so the per-signature cost
// reflects only the modular exponentiation with a modulus the compiler never saw.
pub fn Key(comptime N: usize) type {
    const B = bi.BigInt(N);
    const Fe = B.Fe;
    return struct {
        const Self = @This();

        p: Fe,
        q: Fe,
        p_exp: Fe, // dp = d mod (p-1)
        q_exp: Fe, // dq = d mod (q-1)
        p_n0inv: u64,
        q_n0inv: u64,
        p_rr: Fe, // R^2 mod p
        q_rr: Fe, // R^2 mod q
        qinv_mont: Fe, // (q^-1 mod p) * R mod p

        pub fn fromHex(
            p_hex: []const u8,
            q_hex: []const u8,
            dp_hex: []const u8,
            dq_hex: []const u8,
            qinv_hex: []const u8,
        ) !Self {
            return init(
                try hexToFe(p_hex),
                try hexToFe(q_hex),
                try hexToFe(dp_hex),
                try hexToFe(dq_hex),
                try hexToFe(qinv_hex),
            );
        }

        // Same as fromHex but the components arrive as raw big-endian bytes
        pub fn fromBytes(
            p_be: []const u8,
            q_be: []const u8,
            dp_be: []const u8,
            dq_be: []const u8,
            qinv_be: []const u8,
        ) !Self {
            return init(
                try bytesToFe(p_be),
                try bytesToFe(q_be),
                try bytesToFe(dp_be),
                try bytesToFe(dq_be),
                try bytesToFe(qinv_be),
            );
        }

        // Derive the Montgomery constants once, from the parsed CRT components.
        fn init(p: Fe, q: Fe, dp: Fe, dq: Fe, qinv: Fe) !Self {
            if (p[0] & 1 == 0 or q[0] & 1 == 0) return error.InvalidKey;
            if (p[N - 1] >> 63 == 0 or q[N - 1] >> 63 == 0) return error.InvalidKey;
            if (B.geq(&dp, &p) or B.geq(&dq, &q) or B.geq(&qinv, &p)) return error.InvalidKey;

            const p_rr = B.rSquared(&p);
            const p_n0inv = negInv64(p[0]);
            return .{
                .p = p,
                .q = q,
                .p_exp = dp,
                .q_exp = dq,
                .p_n0inv = p_n0inv,
                .q_n0inv = negInv64(q[0]),
                .p_rr = p_rr,
                .q_rr = B.rSquared(&q),
                // qinv * R mod p = montMul(qinv, R^2) since montMul folds in one R^-1.
                .qinv_mont = B.montMul(&qinv, &p_rr, &p, p_n0inv),
            };
        }

        // Big-endian bytes (up to N limbs) into little-endian 64-bit limbs.
        fn bytesToFe(be: []const u8) !Fe {
            if (be.len > 8 * N) return error.KeyTooLong;
            return B.fromBytesBE(be);
        }

        // Big-endian hex (up to N limbs) into little-endian 64-bit limbs.
        fn hexToFe(hex: []const u8) !Fe {
            if (hex.len > 2 * 8 * N) return error.KeyTooLong;
            var bytes: [8 * N]u8 = undefined;
            const decoded = try std.fmt.hexToBytes(bytes[0 .. hex.len / 2], hex);
            return B.fromBytesBE(decoded);
        }
    };
}

// Default key material per modulus size, used when no key is passed on the
// command line. The hex strings are the big numbers from the ASN.1 PKCS#1 private
// key (the two primes, both CRT exponents and the coefficient); parsing still
// happens at runtime. Each `sig_hex` is the OpenSSL PKCS#1 v1.5 + SHA-256
// signature of the benchmark message, used as the reference test vector.

pub const default2048 = struct {
    pub const p_hex = "f25f7b542cd1a36802bc14b2fa1b66cdd9b12e6c1fc0fdfebbf26c419c63d5974d3edd093553999a39beed5c4bf8c71e12b83348a5beead2115ecaecf4a69911c13084689879fd0fb9d133a39e75681aa781115ca8273ddf8ec14c53b861ad3679109c3a37746d3b57caa4e2e152d32baad2d95371de1728ba106602116821c7";
    pub const q_hex = "c091732854f87cbb00114606d2232b63de13a2d92e0b5702cb66d812836dd21cb86bb5b4b29c3d2333c4deb75c22d561e0fcb868011a702e403370d91b348a12af1661604591d7cd3fa7055a94f6a7caef4f65c9920d792a30c2cd6669621243f3aa91229aba9998e7a83785bfa8ab23c3efd1dd7cdcd63c1062abd4d39f5a3b";
    pub const dp_hex = "e5c5e3336fb1e68a0a5da7f9ece5e1563194a97fd3b2b098b83120b42ac0f29297a68b01d9ce4186564c4cd5fd28020cde8e46000f31a98830f37ec9993dff4b37acf939f7a35e67742f8217117818937c4cfddaab87583f0224fa693c194d8ea0c34078686e35c7d678c44c5a749cc17f1698f564b3b99ce097ff3ce2a7a7ad";
    pub const dq_hex = "b79efa0c0f5a12b5cdceaad37e3502feeb9815c4b9df1e4d0fdf355211f8fa4d609d745aa5a5cdb66f7ade54418b05a59b7fdfe76c85e54a74f59839ad735fe58906f23b769b270814161348d89a8a4d3bfc9db6a38a2d6b49abb7685c3ca3e61fc71935c20d04c184c4268d66c052d07bd9866888d39b8512aac3e6e1142659";
    pub const qinv_hex = "64a8aa6ec67a7f53d85d2b8101185745f7a9cee70d73c2317dace365e667f6a5fa9dc9f9ea05fccf4f716d302f9c8f07d4c926f2c805520ff614a1f25b625f54b812b7fb1806fe4f867d70e3d8246a1c7ac36dfe0343737ca91af9e94a6079275a6baf5020f3493e85766cbf10b3188b1291713403a3ab1f3adbb87bf9139f7f";
    pub const sig_hex = "4a419fbe406daf9f89e136e3cc084c26c8ac71061c9b616c71ce6d0b62a719e7c01a51ec1beb9c38ef7fa1c39c136b0414cc84b8224067c0db5af8af1c1d05a2c6c93a2bc1004a810d474292df522016cbcd64e9c04730304fca8d39a276d7d2a42c34647010e9c451469eee4bca2434a41c4a4110506b5830a50727652861b8fa380b57fff94580a91499aa24629d39ba7448fc2e87ae90c432d77d9773cd6464ca3740394923fd4bbcc20d1951e34c1819b4727a8463e221c30a0404c8122f06a894fc9ffce25af407701c8b2699bffeb6bb3b825c84a056212588826909cec3c91ef185c9221e9f2270786d8a23007123fb6962524fe40dc1166710670ec2";
};

pub const default3072 = struct {
    pub const p_hex = "e865a0bdadab735c6c161813ffbef99255545a4d36a3f61dadaed43a5f50d5e91d2208b7f61b94a7ab9130d6f38bfa364f0a779b6bce3939554af641eae89bc67358e8e417e534612407541618434788cb9ff4e14cdf27718b971957936e9a25be77b70f580a005c71fa5a778c9271a3cf4d541f6232102d372e07f9b58996e9a0708979849aea831d0a99fb42528e6bba5c095f0c5d5acedea8f844e325aee8fffb914a82b95a341c2cfe9e59088b3e316772955f1a271e91089c814587c3fd";
    pub const q_hex = "bbb4ac360e81da022b0a6df53daa6b0c3fffc24497781943ce677073b3f351ecf83b357250cc84b5bb58a63618d99a540ff765665e0eb44707ab971ff007dadfa682d14d9bf5e00515ebddeb4aed4315bf4ba04e3b949ef30527bb9e832f585889d84af88676a674b89d51e2b484994b895db42b2034991c8218af3df53f04f02e3430c935d3e6ea26f2fc3b96b8c457813778e6587963c91700bb6fe7bb11dab114655c518a5b838f1ab1dc77ade1306e6ac7cd86569eb85e23fdb69b3c8193";
    pub const dp_hex = "5b4be173e2902247c2a6835b07f36c7412558b0c1e551750dd747b275b5e944a7a096ec76645bb868b1e04c3ccf5c69c233d0773e54c24aae359099927c1adc0ae7bd532163912f4be84aa81eb9232be08d094111673ec38ed0fb502f48654c45329109f5484c95387eb443306e459047361fb9440ad4e319525de38391b0e5045993048aed1752380fb3336c3fd4eb9ff823ca43c65485150a3acb4d34f7081545eeddb09b3eb3de17bc3a34d72cfd0e4f3b0ce018872a9cd6c469f7a4335b9";
    pub const dq_hex = "57f44801a87896240ff0fa274136faa429d4f93dd4cff4debdf7e04c8714cbddc34f5332f6c36ea80d5a73bfc3932b6a9a74ad71f33ee6a0a5ea748d059758ab15c614b74e0e3f6382ab1c38a5ca5975f646449e83f2972c7ecce870553e39227bacfb2c4b2d8bc003c5cbd9f40672226002a56ad3d371af5712a402df4921523e043c9bfbfa0828ce096bc1ac5575c31f0c543d7355a63952eb07e95ee75c6d622e917459cd0026bc46a0f312ad4a68bc4492cd2e56a656f3dddf83d267debb";
    pub const qinv_hex = "a389f229b396425ff57dd4cfb3e8e0a7c51502335d173547566a41c411919c254bc0ccf3e34c9eb08b27956d00a6bf6a41e1eb678cb47f5d462c4a3c938d2484048b28cfa17925339e069ba71c38024e1516bc70f86d73d3e0963a65daeb1858126d635e533809714b1165e076b49878440d7c0198d9c250f27f68266f44754e0a0447fe244e092f12279229d240b8f879a7a6d249458bb16e9825c2634f12478ce7382e53d5839bd4e57e46f8406b407a2a83b3c4e65e94d19e491c17eb78b5";
    pub const sig_hex = "34d182663bbbd8f17a398c58f67050341578c2a14c3fcd23ff97d548b791c965c11eaf85e73aa0b4b3681fec3cc195adf152435807e2d7d174a6d343804289cf2d60d11e016a4ecc59f0054e3c58180da73f61626a1e6a7c45993ae38609ac157e4472856508184810d77f94a37a0eefbabfcb67a755ae1f2828840656e880f30f59e8efc171a2a435690cf0bf51c1bf1f9f583cbafe7a15d53c40962f1f71466e5532195edb53221f3742d8f39b3a9e028f84d86f4163b591bf05fbee10008da14223232c5ab4a1ff22790df904f05101b6c07d47fae2d39c230f581f4ebcbfe2b8ac37b588bde34aace89b075139f0cad3917d5029927cdfcb9cec879ff05dbe82a4cd4eff9843daf13131603381f9d85cd280fe00de62a5a4f0e7b7b2f63fe2a99f66f0ba78ef2bdab95b6eb38300de28649e02471e49c2d96354ae63356a106e14ee1fa04171c1e2e2cf7e6aae40077117ee19a2e643fa2d4d0ba0b53d8d3c31dfc2041a70ab4fa0d108ba095d52a189280700cb9efbb66eda28b7904b8b";
};

pub const default4096 = struct {
    pub const p_hex = "fb2a1320a90ee6c86e32e58dbdb2ee83ef3b0d469777c03dfa00100dfdba1bcc7fc81436609a1eb48bcc9d3fed834c92eeda92b98f94fad6de1154a64df92d71246e8e3c47117c891f9b11735c4e26da82240d8682c260eaf7ea809ca4e650f6b94792ff6e6fc21639faba5e42d28a0ea10f964faf8fe6617ca9cd6e3eb8a11b9dda9711d94e445d65442a319756873ee9c1f07c1e4fc0b70004361144e7a1dbee22f6506de29568e85cc88b2c55fd65092800f0e3ef7e03086739119c40e1ac3d7a02236956c400bc0e1f774782a26905ce5ac71388231273be097b571dc53f20f83154a173ea9b003708ade10e9df8aa1e74556ed92f21ba4a3c90c8c3ef17";
    pub const q_hex = "d79723f52ffb8aa5b3d538a8b4cc70986437e330f35c258f62e1c798e81e120d87d52e1e1d871ac274be4a34bdc1c9e2ca8344822ace5e4a2fbe43775725056d6e8592bbbab015f659f483725a5bcf796d14527f1f224420955fc1985ad18a12a08e1005aa417669407867f3dbad2a686112804f284b0052444e4fdcee5f5a9de1ae1fc6ba0b8126ca555bfde9a4ae0ee646b5f5c8536a066bab025e05db8d37ba1de45f150627cafe42313fe9c6ea842d96f2de84e60021d4fe863fcf5717ecf6fe6e6f39698f35ae71bf561b9d1c30eebd600fe4505fccf691b9f7acffdc284d505383efc9e6590ad224e03c4583ee4e1e02aff9ef77eeff5b9ec29b0359eb";
    pub const dp_hex = "cd95e70a38d765b871db5f62e1fff09435e1d4401003896c31929391a03a123f15e924024e9858c1d81ca82a87b38d9e47bcc994f21e342464a932ecddae34b003ee2aa6d4554fe6bde424289549b32bf092aa2f8c20a74c2d99d9a45ea5d767dcc8e55e077b9b16ae66b8de273c469d2ae0a35c9e8bdf3bb4db18b840c6c7b8df40e99f468c76112caedb0ab4a1b31aa0248b404d5f6293688409eda0c5290be8a4dd91802093c3c74f0b28402632bfdcfacdaa6028ccb096d447364efc1cbceba54ed2c58aabed1e01416855346cd42258829da93329e214b35cf7849b6db4fabbad4564d2891a4ed6bd57f67c0c7a5a658b3bd2fc1b44344447c70b4eb609";
    pub const dq_hex = "52bff5924ff789f12e448239e723ad7820c77ed1b42743577509da75eb6a575d902c984600e971b0ffe466513620a2e005013b9386e0ad3a6676ee28696f9154be9e5082f4165067bd8167cec5b605bdc2cb911ab01593f6b9bf066cf737047b3fdb277535336942def71857769351fabc7fc07621ae2012739b6776129cd10856ae620e022d16469055113935abfb0f46fe0f2ba6d7b5937f52255777821d032dd1f96d3181aa56751f6d0dee2a66ab9360241a9b02393cc3276ada253875bb83d68706f40f7b638c70a6936387fb6120d1d984600b25aa635dedf68e15ab2860fc9b01c25149b415be315f4c63164faaf643ebcdd047c599884e38be0d1c3f";
    pub const qinv_hex = "39e5d481418f5c754ff1fb3c9aaee8905d76e95091134bb48bb0206172b8eb0aff5d1cac2fc2bc06bb465f8f0b4c30d9156789f57890807f3e61b91a6d510b3ad36e9ea01a1e9c40d98e6a21f6f5e188751b13712b1e0e3469bb14b9715b3a43483813156c6b0b20ea96fc33c3154a2b3d79d8b294d5b82dbb8c3ae7aa433a9ee8cc0ae0aff4605bc7921c41b01b96b1ffca5771f201176d2529e9cf2f4993cf69a055889f45f38462089392670a7421780c8ed031dd11160ef071c612c898c14841de917e0052ed3800e56cf8f81f28ee54c93f58bf07ebf53e3e0f5e26fd784b7ef539c87aa8c34b122a0224f05ea1f63b58233ef801ad8a0e18b8b136dba5";
    pub const sig_hex = "b6aa8323eea329987e604742c8d81aa146bb925bd9e3361f1c8361a0737cb75b4c9d8e370f6a2375de35fd3282c5f099d9ed42394858060a5377ebd9d0aee2cbc88a7183e82fb00f3864bf8de00137964907e28049e6cca652974f8fa15b68cf651a4ddbd6afefa7a8d2db3f6ad4f4d045bd54cf1cf668248594c1bf2c1cb34619e0e6812380abf2f456b90b74660c8bf4409b0a9aaedde63042d0cbefebefebb2c9f92b83bc82d27a39223420e18b9b44a2bf8774ae730e66cb35258b8c35f3ffcba2ed76842d7f93e9d86a0312c58a5e29d89d9a851543501b5b5c14d7b2ccbffc55c092d91229f0e3ac673b439a7e6ec8d8445d8634a4ec40e39a1f52a95d6e57e5a854d36dcc2be87ac8bd69bece3f9c65e8dd6b0210dcff35faa595c79f436cda2c36dc3d3606dcfc7917d356a92bd715acfecdaff0ec2e71585472d6e2314c6877cbf2734c0075c194864f2f0f2b33a9eb511296c669cdf8d96d2da3ba00403dff544a6c868fb3e38a95931701e9bd4eef5e869859865b2c1b5156e21af3ce0a140441bc712b429e582af78e9b79c8cabc6b38df1e54933689851011650bebdcf5d27a40d724c34c12f566d9f353c457dc23a8ec86d0e9f724068145a4eb29bb8abb93ed5de1cb26840539984c5dca2d7e85507fb7fd9a5bb72d3daa47e9d17001ae61834a54bccf9bde7ef568db13c0556817aab9d904ad95bc1107fa";
};
