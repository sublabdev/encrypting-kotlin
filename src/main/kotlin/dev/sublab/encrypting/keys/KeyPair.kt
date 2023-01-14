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
 * A factory for creating a `KeyPair` object
 */
interface KeyPairFactory {
    /**
     * Loads seed to create a `KeyPair`
     * @param seedOrPrivateKey The seed data or private key which is used to generate a `KeyPair` object
     * @return `KeyPair` object with private and public keys as well as with an interface that provides a signature
     * engine, message signing and signature (and message) verification interfaces.
     */
    fun load(seedOrPrivateKey: ByteArray): KeyPair

    val seedFactory: SeedFactory

    /**
     * Generates a `KeyPair` from a word count and a passphrase.
     */
    fun generate(wordCount: Int = DEFAULT_WORD_COUNT) = generate(DefaultMnemonicProvider(seedFactory).make(wordCount))

    /**
     * Generates a `KeyPair` from a mnemonic
     */
    fun generate(mnemonic: Mnemonic) = load(mnemonic.toSeed())

    /**
     * Generates a `KeyPair` from a phrase
     */
    fun generate(phrase: String) = generate(DefaultMnemonic.fromPhrase(phrase))

    /**
     * Generates a `KeyPair` from words
     */
    fun generate(words: Sequence<String>) = generate(DefaultMnemonic.fromWords(words))
}

/**
 * An interface that holds the private and public key-pair;
 * and also effectively hides the specifics about which `SignatureEngine` is used
 */
abstract class KeyPair: Signer, Verifier {
    companion object Factory

    /**
     * Signature engine used
     */
    abstract fun getSignatureEngine(byteArray: ByteArray): SignatureEngine

    abstract val privateKey: ByteArray
    abstract val publicKey: ByteArray

    /**
     * The default signing implementation
     * @return The signature
     */
    override fun sign(message: ByteArray) = getSignatureEngine(privateKey).sign(message)

    /**
     * The default verification implementation
     * @return A Bool value indicating whether the verification was successful or not
     */
    override fun verify(message: ByteArray, signature: ByteArray)
        = getSignatureEngine(publicKey).verify(message, signature)
}