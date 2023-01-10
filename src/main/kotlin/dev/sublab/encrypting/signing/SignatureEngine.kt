package dev.sublab.encrypting.signing

interface SignatureEngine: Verifier, Signer {
    val name: String

    fun loadPrivateKey(): ByteArray
    fun publicKey(): ByteArray
}