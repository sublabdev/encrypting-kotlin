package dev.sublab.ed25519

import dev.sublab.hex.hex
import dev.sublab.encrypting.SignatureEngine
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

class Ed25519(private val byteArray: ByteArray): SignatureEngine {
    init {
        Security.addProvider(EdDSASecurityProvider())
    }

    private fun keyFactory() = KeyFactory.getInstance(EdDSAKey.KEY_ALGORITHM, EdDSASecurityProvider.PROVIDER_NAME)
    private fun curveTable() = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)

    private fun privateKeySpecFromSeed() = EdDSAPrivateKeySpec(byteArray, curveTable())
    private fun privateKeyFromEncoded(privateKey: ByteArray)
        = EdDSAPrivateKey(PKCS8EncodedKeySpec(privateKey.withPrivateKeyPrefix()))

    private fun publicKeySpec() = EdDSAPublicKeySpec(privateKeyFromEncoded(byteArray).a, curveTable())

    override fun createPrivateKey(): ByteArray
        = keyFactory().generatePrivate(privateKeySpecFromSeed()).encoded.withoutPrivateKeyPrefix()
    override fun publicKey(): ByteArray
        = keyFactory().generatePublic(publicKeySpec()).encoded.withoutPublicKeyPrefix()

    private fun signature() = Signature.getInstance(EdDSAEngine.SIGNATURE_ALGORITHM, EdDSASecurityProvider.PROVIDER_NAME)

    override fun sign(privateKey: ByteArray): ByteArray = signature().run {
        initSign(privateKeyFromEncoded(privateKey))
        update(byteArray)
        sign()
    }

    override fun verify(signature: ByteArray, publicKey: ByteArray) = signature().run {
        initVerify(EdDSAPublicKey(X509EncodedKeySpec(publicKey.withPublicKeyPrefix())))
        update(byteArray)
        verify(signature)
    }
}

val ByteArray.ed25519
    get() = Ed25519(this)