package dev.sublab.encrypting.mnemonic

import java.util.*

interface MnemonicProvider {
    fun make(wordCount: Int, language: String = Locale.ENGLISH.language): Mnemonic
}