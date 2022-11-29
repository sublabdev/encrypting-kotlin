package dev.sublab.sr25519

import dev.sublab.encrypting.signing.SignatureEngine

class Sr25519(private val byteArray: ByteArray, private val label: String): SignatureEngine {
    private fun privateKey() = try {
        MiniSecretKey.fromByteArray(byteArray).expand(ExpansionMode.ED25519)
    } catch (_: Exception) {
        SecretKey.fromByteArray(byteArray)
    }

    private fun publicKeyFromRistretto()
        = PublicKey.fromByteArray(byteArray)

    override fun loadPrivateKey() = privateKey().toByteArray()
    override fun publicKey() = privateKey().toPublicKey().toByteArray()

    private fun transcript(message: ByteArray) = SigningContext(label.toByteArray()).bytes(message)

    override fun sign(message: ByteArray) = privateKey().sign(transcript(message)).toByteArray()

    override fun verify(message: ByteArray, signature: ByteArray)
        = publicKeyFromRistretto().verify(transcript(message), Signature.fromByteArray(signature))
}

fun ByteArray.sr25519(label: String = DEFAULT_LABEL)
    = Sr25519(this, label)