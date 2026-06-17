//===----------------------------------------------------------------------===//
//
// This source file is part of the Stream64 open source project
//
// Copyright (c) 2022-2026 fltrWallet AG and the Stream64 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.md for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Stream64
import Testing

@Suite struct GolombCodedSetTests {
    @Test func writeReadRandom() throws {
        let input = (0..<100_000)
            .map { UInt64.random(in: 100_000...10_000_000) * UInt64($0) }
            .sorted()

        let gcs = GolombCodedSetClient.stream64
        let result = try #require(gcs.encode(sorted: input, p: 19))
        let all = gcs.decode(compressed: result, n: input.count, p: 19)
        #expect(all == input)
    }

    // Real mainnet basic-filter GCS payload (110 elements, p=19). Decoded WITHOUT
    // appending the historical 7-byte zero pad — the bounded C reader handles the
    // tail safely on its own.
    @Test func realData() throws {
        let data = "07e0aa6befa80967411db98419c1b0ca0fbb023839ce158f30ae8650aef16a7c0cc3acd2127fca7cf3986f3bf928aa22126c6512d364d093ced658950ac31c3efd7ed18245212de64371bc621600c54e0b1e01113079e0b09404ddedafb806e0daa0c7832bbed12f9312cb81fdda63ecfacb5c07bd2c3d7f57f82f1df5b8298b2c1a9dab953ac8e3c58dc9516d8c05a062d8e14fe4c505081d6cdd21355660b3a6ae3b9a00f5806e7e5cd09c6b12d052aad0dd3f99b09fbe120ac4c0ebca445274be1d6802a33e228b74d9bb8861bcc97b29eae719b1d0365d900b2ff23d6e0ff2000beadb6cb29f4cda6658c6b876324b2cf7ea680869b59df4f11fb9f4cae81cd69a6fa69d9a01a44cbde012e5f4ed7cf425ffec8813a4c0f8fbfa512769f05f00".hex2Bytes
        let client = GolombCodedSetClient.stream64
        let decoded = try #require(client.decode(compressed: data, n: 110, p: 19))
        #expect(decoded.last == 85401311)
    }

    // Testnet block 1938592 basic filter. The 3-byte varint element-count prefix
    // (0xfdb601 = 438) is dropped; the remaining payload is decoded directly.
    @Test func testnetBlock1938592() throws {
        let bytes = "fdb6018c9a98c944ed77a51bc88d131af57614af061f9c81474d7a2713fd20dd2f04104b40fd854b9a555f1eb1371b6399569815a3a74081adb0f37e20035e34eefd73695b46d5bf1caf8bd74f38d8def32e6222a2ce88d0707bb9e1c07b6beb9096121debb94971c15956abafdeaa7661c88b170ebffe8fdc091ef78a5ed8e02b83bc297701f2a1e9ccea3acd0f54044ac98dc1541ef26a260e4dc40aff11d7c6cc4c43a6ba6a0346d519ad3ce8bbc22ff62063ac35296a2e1ba1b9af11e68e15766213142ced336e32d24f9ae5a775c0972ff0da5ec80618fe2c346e8ba2ad7ee2038454dc237890e461c6c6adac3f95b0d17c823695177b9e0e73c16bd19b770cdb39ae324b988ac950aa018ef0a5a97bcf00cda816c946fde2471494d55d5b330b2d96a61eadb9814ea871a7bfb7096a3056bb68614321812012841e6b8dcb212f815299d7309da67e9e444b7e15ab19057f8a9dcb64f74ebda70eb8ad3ae809ac79fb5a1cd89cbec98d63ddfaa2ed7dd3152164c8d811683039598d52171bcbed96b8a138ed244740c8bbac664626079efee7be258b69c3b10ddbb91fa853162853b4609617a704a281aa8a27e603a52d48b45c58ce3602ee39a4f1d7352c1593fbbfebb5817b17bb8f2c981e34c4e65f1da4caa5bf6d27302119ded8d49fa4a406af89e2d83ddef982bb40946e478683405ee217c080d51dbcbbd69283235f616b503844d1944c83132d7a08c00a80888374abc16db5370d8a0e18cd147239201ff2327cd4d4c687d581e2d9a1aa795b25133cf372156e78746522d74404be32dd77dc8c0d4b8fee597f0a78b3595c00a55e58f955bb2c203063864c43d1a466a68a79fc5ccf5465907e35f84a646b97eb5a3a329eedf849cc671039a581c589cd3c4cc992e768ed3a1d617ff22690831c52741ed3e97bbd0d2fb94a4a01c9e04cb8cdd4dda871e932445cebc8500aa532a132719b68d34fd285e9e1367c7ae02d0098858d755796db8bba30c2c5d30b36a7277e464878450c6961ed24bec9912207f033404ec1f70e2c3229964d802dbef236133e83521f8277b495f82e9f5eeeb1346865ad593353949cdfac66009cdcf610d39005ea46bfc1678f6b14662f53d6d9bb55c68529cb3b99fe34ff462e51ad36552ec450fbe6980c83036b5f8988207e839a87f92e22e0d80407164b00a5800583e2f20f501fff82cc7b3df61606a7fa92c45be6774e7a442691ce5817311fe93e0368b4603b75a2c73735c75f2476e57764275926f8d37246e82f58cc06aa628f8b8c006822c361e4f7be5c01630ee9d651b37e1a9e003f1e02e8917a177ec4bb5ec124eeff15c462543e2c2ecea7efc7936b43fa5591dec88bd341c1b28be4195794236f3d95010e5f1119103fa2537b645d2cbb26109d7e4d2ec17349b2f4ee381a565aa3b24c097d5524d1c2f97a9027343c2cda76f7a1125f560b2efcb249cebb80ffe720c6e186db84ca4dac49b1995ae0bd0066a281eeb6b4a2ff04a9a93abc92cb979cd49cef93cb175916d2587c700e3aa7b413effc75a2afc420ccb630a74dcc561fb3c910299862a814e565d83601bce70d113adb9a290007eee06366205422b3a2c97213925870"
            .hex2Bytes

        let payload = Array(bytes[3...])
        let client = GolombCodedSetClient.stream64
        let decoded = try #require(client.decode(compressed: payload, n: 438, p: 19))
        #expect(decoded.suffix(1) == [343587834])
    }

    @Test func emptyAndZeroInputs() {
        let client = GolombCodedSetClient.stream64
        #expect(client.encode(sorted: [], p: 19) == [])
        #expect(client.decode(compressed: [], n: 0, p: 19) == [])
    }
}
