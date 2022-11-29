package dev.sublab.encrypting.mnemonic

interface Mnemonic {
    val wordCount: Int
    val words: List<String>
    val entropy: ByteArray
    fun toSeed(passphrase: String = ""): ByteArray
}