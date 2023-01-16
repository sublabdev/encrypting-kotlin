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

package dev.sublab.sr25519

import dev.sublab.encrypting.signing.SignatureEngine

/**
 * Handles sr25519 encryption
 * @property byteArray a [ByteArray] to be encrypted using sr25519
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
     * Loads the private key for sr25519
     * @return A private key
     */
    override fun loadPrivateKey() = privateKey().toByteArray()

    /**
     * Generates a public key for sr25519
     * @return A public key
     */
    override fun publicKey() = privateKey().toPublicKey().toByteArray()

    private fun transcript(message: ByteArray) = SigningContext.fromContext(label.toByteArray()).bytes(message)

    /**
     * The default signing implementation for sr25519
     * @param message a message used for signing
     * @return A newly created signature
     */
    override fun sign(message: ByteArray) = privateKey().sign(transcript(message)).toByteArray()

    /**
     * Verifies the provided message and signature against sr25519
     * @param message a message used for verification
     * @param signature a signature used for verification
     * @return [Boolean] value with a result fo the verification
     */
    override fun verify(message: ByteArray, signature: ByteArray)
        = publicKeyFromRistretto().verify(transcript(message), Signature.fromByteArray(signature))
}

/**
 * An access point to sr25519 functionality
 */
fun ByteArray.sr25519(label: String = DEFAULT_LABEL)
    = Sr25519(this, label)