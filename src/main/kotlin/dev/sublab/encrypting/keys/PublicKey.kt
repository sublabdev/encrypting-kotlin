package dev.sublab.encrypting.keys

interface PublicKey {
    fun verify(message: ByteArray, signature: ByteArray): Boolean
}