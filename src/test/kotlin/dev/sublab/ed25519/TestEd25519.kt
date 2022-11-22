package dev.sublab.ed25519

import dev.sublab.hex.hex
import dev.sublab.support.Constants
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals

class TestEd25519 {

    private val testValues: List<ByteArray>
        get() = (0 until Constants.testsCount).map { UUID.randomUUID().toString().toByteArray() }

    @Test
    internal fun test() {
        val seed = "0x355f13340b9db6e5f7aaadb1deea7aecc57a8af4a4587b7f0e24cfa824f48c07".hex.decode()
        val privateKey = seed.ed25519.createPrivateKey()
        val publicKey = privateKey.ed25519.publicKey()

        for (testValue in testValues) {
            val signature = testValue.ed25519.sign(privateKey)
            val isValid = testValue.ed25519.verify(signature, publicKey)
            assertEquals(isValid, true)
        }
    }
}