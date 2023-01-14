package dev.sublab.sr25519

import dev.sublab.encrypting.signing.SignatureEngine

/**
 * Handles SR25519 encryption
 */
class Sr25519(private val byteArray: ByteArray, private val label: String): SignatureEngine {
    override val name = "sr25519"

    private fun privateKey() = try {
        MiniSecretKey.fromByteArray(byteArray).expand(ExpansionMode.ED25519)
    } catch (_: Exception) {
        SecretKey.fromByteArray(byteArray)
    }

    private fun publicKeyFromRistretto()
        = PublicKey.fromByteArray(byteArray)

    /**
     * Loads the private key for SR25519
     */
    override fun loadPrivateKey() = privateKey().toByteArray()

    /**
     * Generates a public key for SR25519
     */
    override fun publicKey() = privateKey().toPublicKey().toByteArray()

    private fun transcript(message: ByteArray) = SigningContext.fromContext(label.toByteArray()).bytes(message)

    /**
     * The default signing implementation for SR25519
     */
    override fun sign(message: ByteArray) = privateKey().sign(transcript(message)).toByteArray()

    /**
     * Verifies the provided message and signature against SR25519
     */
    override fun verify(message: ByteArray, signature: ByteArray)
        = publicKeyFromRistretto().verify(transcript(message), Signature.fromByteArray(signature))
}

/**
 * An access point to SR25519 functionality
 */
fun ByteArray.sr25519(label: String = DEFAULT_LABEL)
    = Sr25519(this, label)