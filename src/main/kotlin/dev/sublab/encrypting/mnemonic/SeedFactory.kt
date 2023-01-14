package dev.sublab.encrypting.mnemonic

/**
 * An interface for generating seed from a mnemonic and passphrase
 */
interface SeedFactory {
    /**
     * Generates a seed from a mnemonic, with a passphrase. The default value of the passphrase is an empty `String`
     */
    fun deriveSeed(mnemonic: Mnemonic, passphrase: String = ""): ByteArray
}