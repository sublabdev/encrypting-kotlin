package dev.sublab.encrypting.mnemonic

interface SeedFactory {
    fun deriveSeed(mnemonic: Mnemonic, passphrase: String = ""): ByteArray
}