package dev.sublab.ecdsa

import dev.sublab.hex.hex
import dev.sublab.encrypting.SignatureEngine
import dev.sublab.hashing.hashers.blake2b_256
import dev.sublab.hashing.hashers.keccak256
import dev.sublab.hashing.hashing
import org.web3j.crypto.ECDSASignature
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Sign
import java.math.BigInteger

private const val signatureSizeWithHeader = 65
private const val signaturePartSize = 32

private fun ByteArray.toEcdsa() = BigInteger(hex.encode(), 16)

typealias Hasher = (ByteArray) -> ByteArray

class Ecdsa(private val byteArray: ByteArray, private val hasher: Hasher): SignatureEngine {
    override fun createPrivateKey() = byteArray
    override fun publicKey(): ByteArray = Sign.publicKeyFromPrivate(byteArray.toEcdsa()).toByteArray()

    override fun sign(privateKey: ByteArray) = hasher(byteArray).let { message ->
        val privateKey = privateKey.toEcdsa()
        val publicKey = Sign.publicKeyFromPrivate(privateKey)

        Sign.signMessage(message, ECKeyPair(privateKey, publicKey), false).let {
            it.r + it.s + it.v
        }
    }

    override fun verify(signature: ByteArray, publicKey: ByteArray): Boolean {
        if (signature.size != signatureSizeWithHeader) return false

        val signatureV = signature.reversedArray().copyOf(1)
        val signatureR = signature.copyOf(signaturePartSize).toEcdsa()
        val signatureS = signature.copyOfRange(signaturePartSize, signaturePartSize*2).toEcdsa()
        val ecdsaSignature = ECDSASignature(signatureR, signatureS)

        val publicKey = publicKey.toEcdsa()
        for (recId in 0..3) {
            if (!Sign.getVFromRecId(recId).contentEquals(signatureV)) continue
            val publicKeyFound = Sign.recoverFromSignature(recId, ecdsaSignature, hasher(byteArray)) ?: continue
            if (publicKeyFound == publicKey) return true
        }

        return false
    }
}

fun ByteArray.ecdsa(kind: Kind)
    = Ecdsa(this) { hash(kind, it) }

private fun hash(kind: Kind, byteArray: ByteArray) = when (kind) {
    Kind.SUBSTRATE -> byteArray.hashing.blake2b_256()
    Kind.ETHEREUM -> byteArray.hashing.keccak256()
}