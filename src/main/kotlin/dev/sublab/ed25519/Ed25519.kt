package dev.sublab.ed25519

import dev.sublab.hex.hex
import dev.sublab.encrypting.signing.SignatureEngine
import net.i2p.crypto.eddsa.*
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.KeyFactory
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

private const val privateKeyPrefix = "0x302e020100300506032b657004220420"
private const val publicKeyPrefix = "0x302a300506032b6570032100"

private fun privateKeyPrefix() = privateKeyPrefix.hex.decode()
private fun ByteArray.withPrivateKeyPrefix() = privateKeyPrefix() + this
private fun ByteArray.withoutPrivateKeyPrefix() = copyOfRange(privateKeyPrefix().size, size)

private fun publicKeyPrefix() = publicKeyPrefix.hex.decode()
private fun ByteArray.withPublicKeyPrefix() = publicKeyPrefix() + this
private fun ByteArray.withoutPublicKeyPrefix() = copyOfRange(publicKeyPrefix().size, size)

/**
 * Handles ED25519 encryption
 */
class Ed25519(private val byteArray: ByteArray): SignatureEngine {
    override val name = "ed25519"

    init {
        Security.addProvider(EdDSASecurityProvider())
    }

    private fun keyFactory() = KeyFactory.getInstance(EdDSAKey.KEY_ALGORITHM, EdDSASecurityProvider.PROVIDER_NAME)
    private fun curveTable() = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)

    private fun privateKeySpecFromSeed() = EdDSAPrivateKeySpec(byteArray, curveTable())
    private fun privateKeyFromEncoded(privateKey: ByteArray)
        = EdDSAPrivateKey(PKCS8EncodedKeySpec(privateKey.withPrivateKeyPrefix()))

    private fun publicKeySpec() = EdDSAPublicKeySpec(privateKeyFromEncoded(byteArray).a, curveTable())

    /**
     * Loads a private key for ED25519
     */
    override fun loadPrivateKey(): ByteArray
        = keyFactory().generatePrivate(privateKeySpecFromSeed()).encoded.withoutPrivateKeyPrefix()

    /**
     * Generates a public key for ED25519
     */
    override fun publicKey(): ByteArray
        = keyFactory().generatePublic(publicKeySpec()).encoded.withoutPublicKeyPrefix()

    private fun signature() = Signature.getInstance(EdDSAEngine.SIGNATURE_ALGORITHM, EdDSASecurityProvider.PROVIDER_NAME)

    /**
     * The default signing implementation for ED25519
     */
    override fun sign(message: ByteArray): ByteArray = signature().run {
        initSign(privateKeyFromEncoded(byteArray))
        update(message)
        sign()
    }

    /**
     * Verifies the provided message and signature against ED25519
     */
    override fun verify(message: ByteArray, signature: ByteArray) = signature().run {
        initVerify(EdDSAPublicKey(X509EncodedKeySpec(byteArray.withPublicKeyPrefix())))
        update(message)
        verify(signature)
    }
}

val ByteArray.ed25519
    get() = Ed25519(this)