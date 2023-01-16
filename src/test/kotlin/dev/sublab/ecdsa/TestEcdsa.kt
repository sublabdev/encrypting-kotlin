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

package dev.sublab.ecdsa

import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.encrypting.mnemonic.DefaultMnemonicProvider
import dev.sublab.encrypting.mnemonic.EthereumSeedFactory
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory
import dev.sublab.hex.hex
import dev.sublab.support.Constants
import java.util.UUID
import kotlin.math.sign
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

internal class TestEcdsa {

    private val testValues: List<ByteArray>
        get() = (0 until Constants.testsCount).map { UUID.randomUUID().toString().toByteArray() }

    @Test fun testSubstrateSignature() = testSignature(Kind.SUBSTRATE)
    @Test fun testEthereumSignature() = testSignature(Kind.ETHEREUM)

    private fun testSignature(kind: Kind) {
        val seed = "0x0637cff0bfebd949172774cbc4d9933e92b6a18eaffd835a79a776a0f6cf92e9".hex.decode()
        val privateKey = seed.ecdsa(kind).loadPrivateKey()
        val publicKey = privateKey.ecdsa(kind).publicKey()

        for (testValue in testValues) {
            val signature = privateKey.ecdsa(kind).sign(testValue)
            val isValid = publicKey.ecdsa(kind).verify(testValue, signature)
            assertEquals(isValid, true)
        }
    }

    @Test fun testSubstrateKeyPair() = testKeyPair(Kind.SUBSTRATE)
    @Test fun testEthereumKeyPair() = testKeyPair(Kind.ETHEREUM)

    private fun testKeyPair(kind: Kind) {
        val seedFactory = when (kind) {
            Kind.SUBSTRATE -> SubstrateSeedFactory()
            Kind.ETHEREUM -> EthereumSeedFactory()
        }

        val mnemonicProvider = DefaultMnemonicProvider(seedFactory)
        for (i in 0 until Constants.testsCount/10) {
            val mnemonic = mnemonicProvider.make(12)

            val keyPairFromSeed = KeyPair.Factory.ecdsa(kind).load(mnemonic.toSeed().copyOf(32))
            val keyPairFromMnemonic = KeyPair.Factory.ecdsa(kind).generate(mnemonic)
            assertContentEquals(keyPairFromSeed.privateKey, keyPairFromMnemonic.privateKey)

            for (testValue in testValues) {
                val signature = keyPairFromSeed.sign(testValue)
                val isValid = keyPairFromSeed.verify(testValue, signature)
                assertEquals(isValid, true)
            }
        }
    }

    @Test fun testSubstrateKeyFactory() = testKeyFactory(Kind.SUBSTRATE)
    @Test fun testEthereumKeyFactory() = testKeyFactory(Kind.ETHEREUM)

    private fun testKeyFactory(kind: Kind) {
        for (i in 0 until Constants.testsCount/10) {
            val keyPair = KeyPair.Factory.ecdsa(kind).generate()

            for (testValue in testValues) {
                val signature = keyPair.sign(testValue)
                val isValid = keyPair.verify(testValue, signature)
                assertEquals(isValid, true)
            }
        }
    }
}