package dev.sublab.ecdsa

import dev.sublab.hex.hex
import dev.sublab.support.Constants
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals

class TestEcdsa {

    private val testValues: List<ByteArray>
        get() = (0 until Constants.testsCount).map { UUID.randomUUID().toString().toByteArray() }

    @Test
    internal fun testSubstrateSignature() {
        testSignature(Kind.SUBSTRATE)
    }

    @Test
    internal fun testEthereumSignature() {
        testSignature(Kind.ETHEREUM)
    }

    private fun testSignature(kind: Kind) {
        val seed = "0xbb32936d098683d24023663036690bad840cd6b8d6975830f8ef490bc3f1f8e4".hex.decode()
        val privateKey = seed.ecdsa(kind).createPrivateKey()
        val publicKey = privateKey.ecdsa(kind).publicKey()

        for (testValue in testValues) {
            val signature = testValue.ecdsa(kind).sign(privateKey)
            val isValid = testValue.ecdsa(kind).verify(signature, publicKey)
            assertEquals(isValid, true)
        }
    }
}