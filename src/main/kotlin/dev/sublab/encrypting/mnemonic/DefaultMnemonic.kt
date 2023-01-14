package dev.sublab.encrypting.mnemonic

import cash.z.ecc.android.bip39.Mnemonics

/**
 * A default mnemonic
 */
class DefaultMnemonic(
    private val code: Mnemonics.MnemonicCode,
    private val seedFactory: SeedFactory
): Mnemonic {
    override val wordCount get() = code.wordCount
    override val words get() = code.words.map { it.joinToString("") }
    override val entropy get() = code.toEntropy()
    override fun toSeed(passphrase: String) = seedFactory.deriveSeed(this, passphrase).copyOf(32)

    companion object {
        fun fromPhrase(phrase: String, seedFactory: SeedFactory = SubstrateSeedFactory()): Mnemonic
            = DefaultMnemonic(Mnemonics.MnemonicCode(phrase), seedFactory)

        fun fromWords(words: Sequence<String>, seedFactory: SeedFactory = SubstrateSeedFactory()): Mnemonic
            = fromPhrase(words.joinToString(" "), seedFactory)
    }
}