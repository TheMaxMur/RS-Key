// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OpenSSL Known-Answer-Test vectors for RSA PKCS#1 v1.5 — the independent
//! ground truth the host tests check this crate against, so the suite needs no
//! second RSA *implementation* linked into the tree.
//!
//! Source: OpenSSL 3.6.2 via python-cryptography 48.0.0. Regenerate with
//! `scripts/rsa_vectors.py`. **Generated — edit the script, not this file.**
//!
//! Encryption is randomised, so a ciphertext is frozen here and we have to
//! decrypt it back; signing is deterministic, so ours must match byte for byte.

use alloc::vec::Vec;

/// The RSA-2048 key's primes and modulus, big-endian hex. Public exponent 65537.
pub const P_HEX: &str = "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea500c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd";
/// See [`P_HEX`].
pub const Q_HEX: &str = "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d";
/// See [`P_HEX`].
pub const N_HEX: &str = "ba8654a65ddb75e8cf593ee635345ac0a64d43bd328849683979bf25928cf46489051bf991cdb56a464d83069048c651b049d0181bc08a1e34cb9130a86c67a6283e79100d6c32dce9ddf852ba94cbe1d2b3c89358096cd48a8c90fcb6089819258e44d92d25b0cc4ab2a9224e4489e2eec8abc13a19f520adec2710f8f8ac21b4cebe99a958fe38fe43b50c97375076c2ff5e98980af0c5a719a417ba8f657328ea95f50936d6f459af093bc864b222f89302e9e9972ff491608f7ef93b509c8a65bad0e51bcbf0d2e43d2c9956d762af1d26a01b776471e39a2338babb4f8a30199cf26dd8dbdccf59ef77912b1b700e59c3a7e327ffbb58b6584b827ed449";

/// An RSA-1024 key: the smallest size the OpenPGP card advertises, and the one
/// width whose 5-field CRT blob (5x64) collides with a `P‖Q` one (2x160).
pub const P1024_HEX: &str = "efb80954c7388f28b0a5a9ea244eab0bc4189272b4ab7ad98808e34167002e9ad20ab9fb62f05625c9f72e8448105439dbdd9502a8b9f7d5798fc1dc8be43cab";
/// See [`P1024_HEX`].
pub const Q1024_HEX: &str = "ed764fec2f76eb5ac58a8d99c6075e8d5f8647e801f25665d187ccad0841e2c6edfee5c3969de9ee4801043b4c2130d98397ba2b5d948070f67b35a87deb1c5f";
/// See [`P1024_HEX`].
pub const N1024_HEX: &str = "de5c2a4ebe7f192a928200b518c06885733e797d25c8858b4795a8da5033f0a40b2e168e5629d453d1dbc1403bed339e4923ebb6bd5059400fe1051e76b217455a1fe64e7434231281f55189f8e5ccb14ddb224d4c9851210d255b563b7cec0a0cdfbefcbee4cf0c96c06b7f12d3fbe13982f8eed25a8f9b01d02380104e3775";

/// An RSA-640 key: 40-byte primes, the width the asm CRT core refuses because
/// it is not a multiple of 32.
pub const P640_HEX: &str =
    "ffe2e4a07c75787c7b8b5b902633f9495f8daf04cd3b6930c04b5879ad1e912291f7f41bcbfe0c57";
/// See [`P640_HEX`].
pub const Q640_HEX: &str =
    "e7c7fbc88104db940a479edc7152958e2f11e0d9dee0891942407246eb9b8642b8fc53d5ecde86a7";

/// `(plaintext, ciphertext)` under the [`P_HEX`] key — OpenSSL built the padded
/// block, so our unpad has to accept exactly what a conforming encrypter emits.
pub const ENCRYPT: &[(&str, &str)] = &[
    (
        "",
        "1cfa400bebdadf622225cfcd4b316cc47cb8425efb937dcad2b4f735f4a7a3cbc48fc45a940635aa9ce88011188ab7a4f4bced0494a657cf76da0f704d7f841b010df756ddda8085a4f5279e6699aedc99391f6eaa6d381c5d599bf1513b422728d2301e6444865bbf39a727e9ad40748c9a2903581ff1eb2863c356796a1ffe238c6bd7bf655d550e17e93a7eee0c83e9c49c7f83735b6037dfef10eeb78df57e22b89c84f8dd83972392f4e5c90de02c848dac8b416446997719708d80d6bb94b07f3921689391e296581e0128f0a2d6efbf4865e23b5e164dd7ed8c23bbdafc04fdd317c6177bb28fc171c8f44aa5ef7674fa16cef906b8d6f59f0c00aa19",
    ),
    (
        "78",
        "3480a69525197d1c43c280bfa0a5cd2fee9fd1b2dcb10fd0bb9a027800d0da411ff8f66e1186cebf108609fa138af95a18148fbd387bf67ac72f15cfd5e50fe6486ed825c7beb37057808b94a03ab0ec3e514c459cb3fd6a96b7533716853bdf55630772e381de8a185ccb23ff322259604f21d1597f2ef4890dd0766e1b6b6acda0bda46ade695e463a6625ea9a990b6ec5892b19724a6c606332a52c880bf66dc05af651a41db6d612e9804c5a91bbc82c8835f5ba503b14152c37172c04e6581d92f27ebaaa222479a09bcddce60dc1eabdc6636e4818485cfe5129cb876e11f6320a9429d385b309400afe781f62aba7e9753a52d08b1e811bc46f1137ab",
    ),
    (
        "612d33322d627974652d6f70656e7067702d73657373696f6e2d6b6579212121",
        "5f97b24dd72607ffcfae9cb69886120f3a6d857c5b5a6a06fc42f7b56c86b2e9ddd31cf15317d851df5d521a4c3317edfa83a347a4e1443c6ae76c50f9dd3811c95769378385c420ec51abb1553cabee9daeea034c7d941c8769b50721ef6e7470b6634761c3538fadd75d04b9b30b40b110fbad62ed46636a14c8f75d6f841e297ed3c4cb7ad26700aaef6acb0f9291e949570537da8d9982e088524581106d67321bdfb35bdc79716da0fb9ce1169485381040d66137b24d424554b18dc862ef240f0e99aad931494ca3dccaf6131728faaf244c9701b5496e8570900b7717bc6af376d0464ce1b6cc6b0b517e9fc1b019ea10d77a199eaf382b2420db170d",
    ),
];

/// `(SHA-256 digest, signature)` under the [`P_HEX`] key — RSASSA-PKCS1-v1_5.
/// The digest is what a host sends as a bare hash; prefixed with the SHA-256
/// DigestInfo header it is what gpg sends. Both spellings owe this signature.
pub const SIGN_SHA256: &[(&str, &str)] = &[
    (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "36c1d85523bb1d80faf843b8a306d22fc35b568d1fc41db0dccc7f4fc6de47cadeb3085bfbbcf69fd696a66cebaab01d86a4009d3d821227b4613673b714d2846e5ef9fa52d3b6438655ef536e6e83f19102769a9124c3a448f3b2ddf8bc58f0fb5e6486a8fb81c83000f65241ff3df0eaab623eadc27ae02a52652c3043ed1c1bc0119f3a28425d28e21a46e3cdbda8365bd813a3f9dab190ce0f2f9de6ccaab0bbc422faa6d65cd0572c39390b3055ec660370a0c34b0d468d72b18116abe62eef8bd25d01563e1ae8c416d4805d0d0c8e9d1658aaec0295bf13c6f27c0e0ed8c548190eaeed576ee311b7fb4fb08b976297c468bf5bf8e48d0e8c32197a2c",
    ),
    (
        "28c18f2586355c31510dbd18986fb9d1e3b94cfa56ab7b02958e0b1e3d9ca1cc",
        "a8029132cf6afff59a5dde7227e52585b1414064edb7df8a5ccdf3bf26c4c0996c2eaa00984cab87b407f08f0282cb68f6d65bb615557f3e68415dbd32a8247b075a5cfdc40d738b7f38fba6e23f31e5142e04249271f030936eff94cf8f299fc561373626aa6930faa30e3d7251739496ac2ebfb008ef6b630fa2e362c6b883d1cd76372b1ff839287682830d60b799e35bc307a0f680aee28022357f42e31e0e46f626ac9be6daea44897a112a86bbfe403f3eb766aa73b1f0a0d2f5d6aec559f78d22f5e064fc6fb419126f5ec7321356163764120c152af0d5b6cd426486ccd1a12e37c9ad2fff64ecd8997cff80d0006413d46fb0aa4c5e0a94bc7dadcc",
    ),
    (
        "9ecb36561341d18eb65484e833efea61edc74b84cf5e6ae1b81c63533e25fc8f",
        "348fcc478b490318b226a30c121e2f69fae1852a0e49b212a8bfeb126f38ec928484376c56b1115add56f112091ed4da2d1b7546f4e9eaf338385280bc03d0d5929f360c662b4d4c8e4a30e20c7b74e875d1d32142dd3180c9acae1400664e3d51f5ccfaf9a06d84b573bd9c9ae1f89fcd77384a0f79d4eb2859c01856e4036c3622c535c96bec2f29e8a39ba5998e2adb2e3cdabeda12aef645dc27b201e716804ab35960b3bc0246c860bbb8ebe66435a6994103925916ae57bf882a1d479ca985363da4c4c29bd039c749190121e4274205c09222cb92b10bc779e3bc1e081583093659f79f1acbdec7fac5274749bf6fa05af44579199e5c1af976da2909",
    ),
];

/// Decode a big-endian hex constant from this module.
pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("vectors are hex"))
        .collect()
}
