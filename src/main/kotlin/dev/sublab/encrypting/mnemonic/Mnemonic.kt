package dev.sublab.encrypting.mnemonic

/**
 * Standard mnemonic interface
 */
interface Mnemonic {
    val wordCount: Int
    val words: List<String>
    val entropy: ByteArray

    /**
     * Generates a seed from a passphrase
     */
    fun toSeed(passphrase: String = ""): ByteArray
}