package dev.sublab.encrypting.keys

import dev.sublab.encrypting.mnemonic.DefaultMnemonic
import dev.sublab.encrypting.mnemonic.DefaultMnemonicProvider
import dev.sublab.encrypting.mnemonic.Mnemonic
import dev.sublab.encrypting.mnemonic.SeedFactory
import dev.sublab.encrypting.signing.SignatureEngine
import dev.sublab.encrypting.signing.Signer
import dev.sublab.encrypting.signing.Verifier

const val DEFAULT_WORD_COUNT = 12

interface KeyPairFactory {
    fun load(seedOrPrivateKey: ByteArray): KeyPair

    val seedFactory: SeedFactory
    fun generate(wordCount: Int = DEFAULT_WORD_COUNT, passphrase: String = "") = generate(
        mnemonic = DefaultMnemonicProvider(seedFactory).make(wordCount),
        passphrase = passphrase
    )

    fun generate(mnemonic: Mnemonic, passphrase: String = "") = load(mnemonic.toSeed(passphrase))
    fun generate(phrase: String, passphrase: String = "") = generate(DefaultMnemonic.fromPhrase(phrase), passphrase)
    fun generate(words: Sequence<String>, passphrase: String = "") = generate(DefaultMnemonic.fromWords(words), passphrase)
}

abstract class KeyPair: Signer, Verifier {
    companion object Factory

    abstract fun getSignatureEngine(byteArray: ByteArray): SignatureEngine

    abstract val privateKey: ByteArray
    abstract val publicKey: ByteArray

    override fun sign(message: ByteArray) = getSignatureEngine(privateKey).sign(message)
    override fun verify(message: ByteArray, signature: ByteArray)
        = getSignatureEngine(publicKey).verify(message, signature)
}