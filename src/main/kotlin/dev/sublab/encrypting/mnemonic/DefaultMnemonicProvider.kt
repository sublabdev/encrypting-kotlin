package dev.sublab.encrypting.mnemonic

import cash.z.ecc.android.bip39.Mnemonics
import java.util.*

class InvalidWordCountException: Throwable()

class DefaultMnemonicProvider(private val seedFactory: SeedFactory): MnemonicProvider {
    @Throws(InvalidWordCountException::class)
    override fun make(wordCount: Int, language: String): Mnemonic {
        val count = Mnemonics.WordCount.valueOf(wordCount) ?: run {
            throw InvalidWordCountException()
        }

        return DefaultMnemonic(Mnemonics.MnemonicCode(count), seedFactory)
    }
}