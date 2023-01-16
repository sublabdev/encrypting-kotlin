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

package dev.sublab.encrypting.signing

/**
 * The base Signature engine that provides an interface for getting a private key;
 * creating a public key; signing a message; and verifying a signature and a message
 */
interface SignatureEngine: Verifier, Signer {
    val name: String

    /**
     * Loads a private key
     * @return [ByteArray] private key
     */
    fun loadPrivateKey(): ByteArray

    /**
     * Generates a public key
     * @return [ByteArray] public key
     */
    fun publicKey(): ByteArray
}