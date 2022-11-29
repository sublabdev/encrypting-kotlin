package dev.sublab.encrypting.signing

interface Signer {
    fun sign(message: ByteArray): ByteArray
}