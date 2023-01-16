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

package dev.sublab.encrypting.keys

import dev.sublab.encrypting.mnemonic.DefaultMnemonic
import dev.sublab.encrypting.mnemonic.DefaultMnemonicProvider
import dev.sublab.encrypting.mnemonic.Mnemonic
import dev.sublab.encrypting.mnemonic.SeedFactory
import dev.sublab.encrypting.signing.SignatureEngine
import dev.sublab.encrypting.signing.Signer
import dev.sublab.encrypting.signing.Verifier

const val DEFAULT_WORD_COUNT = 12

/**
 * A factory for creating a [KeyPair] object
 */
interface KeyPairFactory {
    /**
     * Loads seed to create a [KeyPair]
     * @param seedOrPrivateKey The seed data or private key which is used to generate a `KeyPair` object
     * @return `KeyPair] object with private and public keys as well as with an interface that provides a signature
     * engine, message signing and signature (and message) verification interfaces.
     */
    fun load(seedOrPrivateKey: ByteArray): KeyPair

    val seedFactory: SeedFactory

    /**
     * Generates a [KeyPair] from a word count and a passphrase.
     * @param wordCount a count of words used for generating a [KeyPair]. The default value is set to 12
     * @param passphrase a pass phrase used for generating a [KeyPair]
     * @return A newly generated [KeyPair]
     */
    fun generate(wordCount: Int = DEFAULT_WORD_COUNT, passphrase: String = "") = generate(
        mnemonic = DefaultMnemonicProvider(seedFactory).make(wordCount),
        passphrase = passphrase
    )

    /**
     * Generates a [KeyPair] from a mnemonic and a passphrase
     * @param mnemonic a mnemonic used for [KeyPair] generation
     * @param passphrase a passphrase used to generate [KeyPair]
     * @return [KeyPair] from a mnemonic and a passphrase
     */
    fun generate(mnemonic: Mnemonic, passphrase: String = "") = load(mnemonic.toSeed(passphrase))

    /**
     * Generates a `KeyPair` from a seed phrase and a passphrase
     */
    fun generate(phrase: String, passphrase: String = "") = generate(DefaultMnemonic.fromPhrase(phrase), passphrase)

    /**
     * Generates a [KeyPair] from seed phrase words and a passphrase
     * @param words words used for [KeyPair] generation
     * @param passphrase a passphrase used to generate [KeyPair]
     * @return [KeyPair] from seed phrase words and a passphrase
     */
    fun generate(words: Sequence<String>, passphrase: String = "") = generate(DefaultMnemonic.fromWords(words), passphrase)
}

/**
 * An interface that holds the private and public key-pair;
 * and also effectively hides the specifics about which `SignatureEngine` is used
 */
abstract class KeyPair: Signer, Verifier {
    companion object Factory

    /**
     * Returns signature engine used
     * @param byteArray [ByteArray] for which signature engine should be returned
     */
    abstract fun getSignatureEngine(byteArray: ByteArray): SignatureEngine

    abstract val privateKey: ByteArray
    abstract val publicKey: ByteArray

    /**
     * The default signing implementation
     * @param message [ByteArray] message to sign
     * @return The signature
     */
    override fun sign(message: ByteArray) = getSignatureEngine(privateKey).sign(message)

    /**
     * The default verification implementation
     * @param message a message used for verification
     * @param signature a signature used for verification
     * @return A Bool value indicating whether the verification was successful or not
     */
    override fun verify(message: ByteArray, signature: ByteArray)
        = getSignatureEngine(publicKey).verify(message, signature)
}