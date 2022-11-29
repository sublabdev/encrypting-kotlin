package dev.sublab.sr25519

import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.encrypting.keys.KeyPairFactory
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory

internal class Sr25519Keypair(
    override val privateKey: ByteArray,
    override val publicKey: ByteArray,
    private val label: String
): KeyPair() {
    override fun getSignatureEngine(byteArray: ByteArray)
        = byteArray.sr25519(label)
}

fun KeyPair.Factory.sr25519(label: String = DEFAULT_LABEL) = object : KeyPairFactory {
    override val seedFactory get() = SubstrateSeedFactory()
    override fun load(seedOrPrivateKey: ByteArray) = seedOrPrivateKey.sr25519(label).loadPrivateKey().let {
        Sr25519Keypair(
            it,
            it.sr25519(label).publicKey(),
            label
        )
    }
}