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

package dev.sublab.encrypting.mnemonic

import cash.z.ecc.android.bip39.Mnemonics.DEFAULT_PASSPHRASE
import cash.z.ecc.android.bip39.Mnemonics.INTERATION_COUNT
import cash.z.ecc.android.bip39.Mnemonics.KEY_SIZE
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

/**
 * Factory for substrate seed
 */
class SubstrateSeedFactory: SeedFactory {
    override fun deriveSeed(mnemonic: Mnemonic, passphrase: String): ByteArray = PKCS5S2ParametersGenerator(SHA512Digest()).run {
        init(
            mnemonic.entropy,
            (DEFAULT_PASSPHRASE + passphrase).toByteArray(),
            INTERATION_COUNT
        )

        val keyParameter = generateDerivedMacParameters(KEY_SIZE) as KeyParameter
        keyParameter.key
    }
}