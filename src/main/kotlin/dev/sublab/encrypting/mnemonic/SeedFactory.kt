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

/**
 * An interface for generating seed from a mnemonic and passphrase
 */
interface SeedFactory {
    /**
     * Generates a seed from a mnemonic, with a passphrase.
     * @param mnemonic mnemonic used to get a seed value
     * @param passphrase passphrase used to get a seed. The default value of the passphrase is an empty [String]
     * @return A generated seed [ByteArray]
     */
    fun deriveSeed(mnemonic: Mnemonic, passphrase: String = ""): ByteArray
}