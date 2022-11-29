package dev.sublab.encrypting.keys

interface PrivateKey {
    fun sign(message: ByteArray)
}