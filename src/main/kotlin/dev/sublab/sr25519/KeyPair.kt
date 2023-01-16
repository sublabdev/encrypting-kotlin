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

package dev.sublab.sr25519

import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.encrypting.keys.KeyPairFactory
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory

/**
 * Sr25519 implementation of KeyPair protocol
 */
internal class Sr25519Keypair(
    override val privateKey: ByteArray,
    override val publicKey: ByteArray,
    private val label: String
): KeyPair() {
    override fun getSignatureEngine(byteArray: ByteArray)
        = byteArray.sr25519(label)
}

/**
 * Returns sr25519 keypair factory for a specific kind
 * @param label a label for factory to return, like "substrate"
 */
fun KeyPair.Factory.sr25519(label: String = DEFAULT_LABEL) = object : KeyPairFactory {
    override val seedFactory get() = SubstrateSeedFactory()
    override fun load(seedOrPrivateKey: ByteArray) = seedOrPrivateKey.sr25519(label).loadPrivateKey().let {
        Sr25519Keypair(
            it,
            it.sr25519(label).publicKey(),
            label
        )
    }
}