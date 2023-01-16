/**
 *
 * Copyright 2023 SUBSTRATE LABORATORY LLC <info@sublab.dev>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package dev.sublab.ecdsa

import dev.sublab.hex.hex
import dev.sublab.encrypting.signing.SignatureEngine
import dev.sublab.hashing.hashers.blake2b_256
import dev.sublab.hashing.hashers.keccak256
import dev.sublab.hashing.hashing
import org.bouncycastle.jce.ECNamedCurveTable
import org.web3j.crypto.ECDSASignature
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Sign
import java.math.BigInteger

private const val signatureSizeWithHeader = 65
private const val signaturePartSize = 32

private fun ByteArray.toEcdsa() = BigInteger(hex.encode(), 16)

typealias Hasher = (ByteArray) -> ByteArray

/**
 * Handles ecdsa encryption
 */
class Ecdsa(private val byteArray: ByteArray, private val hasher: Hasher): SignatureEngine {
    override val name = "ecdsa"

    private fun privateKey() = byteArray.toEcdsa()
    private fun publicKey(privateKey: BigInteger) = Sign.publicKeyFromPrivate(privateKey)

    override fun loadPrivateKey() = byteArray

    /**
     * Generates a public key for ecdsa
     * @return public key as a [ByteArray]
     */
    override fun publicKey(): ByteArray = Sign.publicPointFromPrivate(privateKey())
        .getEncoded(true)

    /**
     * The default signing implementation for ecdsa. Returns a generated signature
     * @param message message used to sign
     * @return A generated signature
     */
    @Suppress("NAME_SHADOWING")
    override fun sign(message: ByteArray) = hasher(message).let { message ->
        val privateKey = privateKey()
        val publicKey = publicKey(privateKey)

        Sign.signMessage(message, ECKeyPair(privateKey, publicKey), false).let {
            it.r + it.s + it.v
        }
    }

    /**
     * Verifies the provided message and signature against ecdsa
     * @param message a message to verify
     * @param signature a signature used for verification
     * @return A [Boolean] value indicating whether the verification was successful
     */
    override fun verify(message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != signatureSizeWithHeader) return false

        val signatureV = signature.reversedArray().copyOf(1)
        val signatureR = signature.copyOf(signaturePartSize).toEcdsa()
        val signatureS = signature.copyOfRange(signaturePartSize, signaturePartSize*2).toEcdsa()
        val ecdsaSignature = ECDSASignature(signatureR, signatureS)

        val publicKey = ECNamedCurveTable.getParameterSpec("secp256k1")
            .curve.decodePoint(byteArray)
            .let { it.xCoord.encoded + it.yCoord.encoded }
            .toEcdsa()

        for (recId in 0..3) {
            if (!Sign.getVFromRecId(recId).contentEquals(signatureV)) continue
            val publicKeyFound = Sign.recoverFromSignature(recId, ecdsaSignature, hasher(message)) ?: continue
            if (publicKeyFound == publicKey) return true
        }

        return false
    }
}

/**
 * An access point to ecdsa functionality
 * @param kind specifies ecdsa [Kind]
 */
fun ByteArray.ecdsa(kind: Kind)
    = Ecdsa(this) { hash(kind, it) }

private fun hash(kind: Kind, byteArray: ByteArray) = when (kind) {
    Kind.SUBSTRATE -> byteArray.hashing.blake2b_256()
    Kind.ETHEREUM -> byteArray.hashing.keccak256()
}