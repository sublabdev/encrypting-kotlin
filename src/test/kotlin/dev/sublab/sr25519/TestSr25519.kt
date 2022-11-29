package dev.sublab.sr25519

import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.encrypting.mnemonic.DefaultMnemonicProvider
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory
import dev.sublab.hex.hex
import dev.sublab.support.Constants
import java.util.*
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.Test

class TestSr25519 {

    private val testValues: List<ByteArray>
        get() = (0 until Constants.testsCount).map { UUID.randomUUID().toString().toByteArray() }

    @Test
    internal fun test() {
        val seed = "0xcfdd8f2503e043e9884997c6afcccd3bb30184f7c504de359ce3e591d4f8d853".hex.decode()
        val correctPublicKey = "0x003b6c9a114fb708a99b6fa6753e145f12cf62b9eba095d57a4237570e152f53".hex.decode()
        val privateKey = seed.sr25519().loadPrivateKey()
        val publicKey = privateKey.sr25519().publicKey()
        assertContentEquals(correctPublicKey, publicKey)

        for (testValue in testValues) {
            val signature = privateKey.sr25519().sign(testValue)
            val isValid = publicKey.sr25519().verify(testValue, signature)
            assertEquals(isValid, true)
        }
    }

    @Test
    internal fun testKeyPair() {
        val mnemonicProvider = DefaultMnemonicProvider(SubstrateSeedFactory())
        for (i in 0 until Constants.testsCount/10) {
            val mnemonic = mnemonicProvider.make(12)

            val keyPairFromSeed = KeyPair.Factory.sr25519().load(mnemonic.toSeed().copyOf(32))
            val keyPairFromMnemonic = KeyPair.Factory.sr25519().generate(mnemonic)
            assertContentEquals(keyPairFromSeed.privateKey, keyPairFromMnemonic.privateKey)

            for (testValue in testValues) {
                val signature = keyPairFromSeed.sign(testValue)
                val isValid = keyPairFromSeed.verify(testValue, signature)
                assertEquals(isValid, true)
            }
        }
    }

    @Test
    internal fun testKeyFactory() {
        for (i in 0 until Constants.testsCount/10) {
            val keyPair = KeyPair.Factory.sr25519().generate()

            for (testValue in testValues) {
                val signature = keyPair.sign(testValue)
                val isValid = keyPair.verify(testValue, signature)
                assertEquals(isValid, true)
            }
        }
    }
}