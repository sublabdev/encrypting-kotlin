package dev.sublab.encrypting.mnemonic

import cash.z.ecc.android.bip39.Mnemonics
import cash.z.ecc.android.bip39.toSeed

/**
 * A factory for a seed for Ethereum
 */
class EthereumSeedFactory: SeedFactory {
    override fun deriveSeed(mnemonic: Mnemonic, passphrase: String)
        = Mnemonics.MnemonicCode(mnemonic.words.joinToString(" ")).toSeed()
}