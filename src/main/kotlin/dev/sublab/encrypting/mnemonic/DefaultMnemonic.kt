package dev.sublab.encrypting.mnemonic

import cash.z.ecc.android.bip39.Mnemonics

class DefaultMnemonic(
    private val code: Mnemonics.MnemonicCode,
    private val seedFactory: SeedFactory
): Mnemonic {
    override val wordCount get() = code.wordCount
    override val words get() = code.words.map { it.joinToString("") }
    override val entropy get() = code.toEntropy()
    override fun toSeed(passphrase: String) = seedFactory.deriveSeed(this, passphrase).copyOf(32)

    companion object {
        fun fromPhrase(phrase: String): Mnemonic
            = DefaultMnemonic(Mnemonics.MnemonicCode(phrase), SubstrateSeedFactory())

        fun fromWords(words: Sequence<String>): Mnemonic
            = fromPhrase(words.joinToString(" "))
    }
}