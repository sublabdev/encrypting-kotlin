package dev.sublab.ed25519

import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.encrypting.keys.KeyPairFactory
import dev.sublab.encrypting.mnemonic.DefaultMnemonic
import dev.sublab.encrypting.mnemonic.DefaultMnemonicProvider
import dev.sublab.encrypting.mnemonic.SeedFactory
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory

/
internal class Ed25519KeyPair(
    override val privateKey: ByteArray,
    override val publicKey: ByteArray
): KeyPair() {
    override fun getSignatureEngine(byteArray: ByteArray) = byteArray.ed25519
}

val KeyPair.Factory.ed25519 get() = object : KeyPairFactory {
    override val seedFactory get() = SubstrateSeedFactory()
    override fun load(seedOrPrivateKey: ByteArray) = seedOrPrivateKey.ed25519.loadPrivateKey().let {
        Ed25519KeyPair(it, it.ed25519.publicKey())
    }
}