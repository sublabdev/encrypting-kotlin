package dev.sublab.encrypting.signing

interface SignatureEngine: Verifier, Signer {
    fun loadPrivateKey(): ByteArray
    fun publicKey(): ByteArray
}