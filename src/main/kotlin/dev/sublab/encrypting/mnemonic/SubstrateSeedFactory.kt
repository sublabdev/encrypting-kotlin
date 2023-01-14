package dev.sublab.encrypting.mnemonic

import cash.z.ecc.android.bip39.Mnemonics.DEFAULT_PASSPHRASE
import cash.z.ecc.android.bip39.Mnemonics.INTERATION_COUNT
import cash.z.ecc.android.bip39.Mnemonics.KEY_SIZE
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

/**
 * Factory for substrate seed
 */
class SubstrateSeedFactory: SeedFactory {
    override fun deriveSeed(mnemonic: Mnemonic, passphrase: String): ByteArray = PKCS5S2ParametersGenerator(SHA512Digest()).run {
        init(
            mnemonic.entropy,
            (DEFAULT_PASSPHRASE + passphrase).toByteArray(),
            INTERATION_COUNT
        )

        val keyParameter = generateDerivedMacParameters(KEY_SIZE) as KeyParameter
        keyParameter.key
    }
}