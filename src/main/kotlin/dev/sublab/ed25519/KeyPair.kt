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

package dev.sublab.ed25519

import dev.sublab.encrypting.keys.KeyPair
import dev.sublab.encrypting.keys.KeyPairFactory
import dev.sublab.encrypting.mnemonic.SubstrateSeedFactory

/**
 * A key pair for [Ed25519]
 */
internal class Ed25519KeyPair(
    override val privateKey: ByteArray,
    override val publicKey: ByteArray
): KeyPair() {
    override fun getSignatureEngine(byteArray: ByteArray) = byteArray.ed25519
}

/**
 * Returns ed25519 keypair factory
 */
val KeyPair.Factory.ed25519 get() = object : KeyPairFactory {
    override val seedFactory get() = SubstrateSeedFactory()
    override fun load(seedOrPrivateKey: ByteArray) = seedOrPrivateKey.ed25519.loadPrivateKey().let {
        Ed25519KeyPair(it, it.ed25519.publicKey())
    }
}