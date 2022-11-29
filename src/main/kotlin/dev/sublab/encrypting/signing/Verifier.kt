package dev.sublab.encrypting.signing

interface Verifier {
    fun verify(message: ByteArray, signature: ByteArray): Boolean
}