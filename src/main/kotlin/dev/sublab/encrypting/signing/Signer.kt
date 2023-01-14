package dev.sublab.encrypting.signing

/**
 * An interface for accessing the message signing functionality
 */
interface Signer {
    /**
     * The default signing interface
     * @param message the message that needs to be signed
     * @return The signature
     */
    fun sign(message: ByteArray): ByteArray
}