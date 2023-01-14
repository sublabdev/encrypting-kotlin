package dev.sublab.encrypting.signing

/**
 * The base Signature engine that provides an interface for getting a private key;
 * creating a public key; signing a message; and verifying a signature and a message
 */
interface SignatureEngine: Verifier, Signer {
    val name: String

    /**
     * Loads a private key
     */
    fun loadPrivateKey(): ByteArray

    /**
     * Generates a public key
     */
    fun publicKey(): ByteArray
}