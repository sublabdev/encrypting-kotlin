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
import dev.sublab.encrypting.keys.KeyPairFactory
import dev.sublab.encrypting.mnemonic.DefaultMnemonicProvider
import dev.sublab.encrypting.mnemonic.EthereumSeedFactory
import dev.sublab.encrypting.mnemonic.SeedFactory
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory
import dev.sublab.encrypting.signing.SignatureEngine

/**
 * A key pair for Ecdsa
 */
internal class EcdsaKeyPair(
    override val privateKey: ByteArray,
    override val publicKey: ByteArray,
    private val kind: Kind
): KeyPair() {
    /**
     * Returns the SignatureEngine for ED25519
     */
    override fun getSignatureEngine(byteArray: ByteArray) = byteArray.ecdsa(kind)
}

fun KeyPair.Factory.ecdsa(kind: Kind) = object : KeyPairFactory {
    override val seedFactory: SeedFactory
        get() = when (kind) {
            Kind.SUBSTRATE -> SubstrateSeedFactory()
            Kind.ETHEREUM -> EthereumSeedFactory()
        }

    override fun load(seedOrPrivateKey: ByteArray) = seedOrPrivateKey.ecdsa(kind).loadPrivateKey().let {
        EcdsaKeyPair(it, it.ecdsa(kind).publicKey(), kind)
    }
}