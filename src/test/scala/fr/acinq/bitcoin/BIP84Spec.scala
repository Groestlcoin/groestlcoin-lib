package fr.acinq.bitcoin

import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.DeterministicWallet.KeyPath
import org.scalatest.FunSuite
import scodec.bits._

/**
  * BIP 84 (Derivation scheme for P2WPKH based accounts) reference tests
  * see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
  */
class BIP84Spec extends FunSuite {
  test("BIP49 reference tests") {
    val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
    val master = DeterministicWallet.generate(seed)
    assert(DeterministicWallet.encode(master, DeterministicWallet.zprv) == "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBZRTRVy")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.zpub) == "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzx6o5Ln")

    val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'"))
    assert(DeterministicWallet.encode(accountKey, DeterministicWallet.zprv) == "zprvAceMCrxbVvUavGGXAKTeDaNBZCkDAxU2AYyRB6zMxxPNkTSHX5o3tum6aqqZwqktzPpM5gwPmfUgq7jGRZmNSgRgJWLFiGqhkdNHdEoMRNS")
    assert(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.zpub) == "zpub6qdhcNVVLJ2t8kLzGLzeaiJv7EahaRBsXmu1yVPyXHvMdFmS4d7JSi5aS6mc1oz5k6DZN781Ffn3GAs3r2FJnCPSw5nti63s3c9EDg2u7MS")

    val key = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 0L :: Nil)
    assert(key.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'/0/0")).secretkeybytes)
    assert(key.privateKey.toBase58(Base58.Prefix.SecretKey) == "L4mSsRa7DVFMez7MxcL9cV5ZxeKdMJpJmqJtdcGDz9oJM6sQsNz2")
    assert(key.publicKey == PublicKey(hex"02b61ee53e24da178693ef0e7bdf34a250094deb2ec9dbd80b080d7242e54df383"))
    assert(computeBIP84Address(key.publicKey, Block.LivenetGenesisBlock.hash) == "grs1qrm2uggqj846nljryvmuga56vtwfey0dtnc4z55")

    val key1 = DeterministicWallet.derivePrivateKey(accountKey, 0L :: 1L :: Nil)
    assert(key1.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'/0/1")).secretkeybytes)
    assert(key1.privateKey.toBase58(Base58.Prefix.SecretKey) == "KygxBG82bZ2SrkhaFMLRYPUMLiGmjBANxg7vDCBNVqFhmveTZKWr")
    assert(key1.publicKey == PublicKey(hex"028d25e8e74ddab20f6769f24ef09bf54fa0502b0ab566789da7cd2a565f199c9a"))
    assert(computeBIP84Address(key1.publicKey, Block.LivenetGenesisBlock.hash) == "grs1qy2vlj0w9kp408mg74trj9s08azhzschw5ayp2g")

    val key2 = DeterministicWallet.derivePrivateKey(accountKey, 1L :: 0L :: Nil)
    assert(key2.secretkeybytes == DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'/1/0")).secretkeybytes)
    assert(key2.privateKey.toBase58(Base58.Prefix.SecretKey) == "L3UPrg3xRSrVm3iHEEVLsyuXK54XJSJ9yZBzyEtrB1HNzAwnarPr")
    assert(key2.publicKey == PublicKey(hex"02af1f15ed1969b0de88bb7858b6f0e3a12440f80534e21ee2422c81d644728650"))
    assert(computeBIP84Address(key2.publicKey, Block.LivenetGenesisBlock.hash) == "grs1q4v3e7r759yegjtcwrevg5spe5vfvwkhhwz2zca")
  }
}
