package dev.sublab.ecdsa

import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.encrypting.keys.KeyPairFactory
import dev.sublab.encrypting.mnemonic.DefaultMnemonicProvider
import dev.sublab.encrypting.mnemonic.EthereumSeedFactory
import dev.sublab.encrypting.mnemonic.SeedFactory
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory

internal class EcdsaKeyPair(
    override val privateKey: ByteArray,
    override val publicKey: ByteArray,
    private val kind: Kind
): KeyPair() {
    override fun getSignatureEngine(byteArray: ByteArray) = byteArray.ecdsa(kind)
}

fun KeyPair.Factory.ecdsa(kind: Kind) = object : KeyPairFactory {
    override val seedFactory: SeedFactory
        get() = when (kind) {
            Kind.SUBSTRATE -> SubstrateSeedFactory()
            Kind.ETHEREUM -> EthereumSeedFactory()
        }

    override fun load(seedOrPrivateKey: ByteArray) = seedOrPrivateKey.ecdsa(kind).loadPrivateKey().let {
        EcdsaKeyPair(it, it.ecdsa(kind).publicKey(), kind)
    }
}