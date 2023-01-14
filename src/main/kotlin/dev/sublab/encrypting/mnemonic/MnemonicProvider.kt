package dev.sublab.encrypting.mnemonic

import java.util.*

/**
 * Interface for a mnemonic provider
 */
interface MnemonicProvider {
    /**
     * Makes a mnemonic with specific count of words and language
     */
    fun make(wordCount: Int, language: String = Locale.ENGLISH.language): Mnemonic
}