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

import cash.z.ecc.android.bip39.Mnemonics

/**
 * A default mnemonic
 * @property code mnemonic code
 * @property seedFactory a seed factory
 */
class DefaultMnemonic(
    private val code: Mnemonics.MnemonicCode,
    private val seedFactory: SeedFactory
): Mnemonic {
    /**
     * Returns words count of mnemonic code
     */
    override val wordCount get() = code.wordCount

    /**
     * Returns words
     */
    override val words get() = code.words.map { it.joinToString("") }

    /**
     * Converts code to entropy
     */
    override val entropy get() = code.toEntropy()

    /**
     * Gets seed with a passphrase
     * @param passphrase a passphrase used to get a seed
     * @return A seed
     */
    override fun toSeed(passphrase: String) = seedFactory.deriveSeed(this, passphrase).copyOf(32)

    companion object {
        /**
         * Returns a mnemonic using the provided phrase and a seed factory
         * @param phrase seed phrase used to get a mnemonic
         * @param seedFactory seed factory used to get a mnemonic
         * @return Mnemonic from the provided seed phrase and seed factory
         */
        fun fromPhrase(phrase: String, seedFactory: SeedFactory = SubstrateSeedFactory()): Mnemonic
            = DefaultMnemonic(Mnemonics.MnemonicCode(phrase), seedFactory)

        /**
         * Returns a mnemonic using the provided seed phrase words and a seed factory
         * @param words seed phrase words used to get a mnemonic
         * @param seedFactory seed factory used to get a mnemonic
         * @return Mnemonic from the provided words and seed factory
         */
        fun fromWords(words: Sequence<String>, seedFactory: SeedFactory = SubstrateSeedFactory()): Mnemonic
            = fromPhrase(words.joinToString(" "), seedFactory)
    }
}