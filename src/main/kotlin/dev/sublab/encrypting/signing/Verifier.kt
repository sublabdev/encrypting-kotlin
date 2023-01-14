package dev.sublab.encrypting.signing

/**
 * An interface for accessing a message and a signature verification functionality
 */
interface Verifier {
    /**
     * Verifies the provided message and signature
     */
    fun verify(message: ByteArray, signature: ByteArray): Boolean
}