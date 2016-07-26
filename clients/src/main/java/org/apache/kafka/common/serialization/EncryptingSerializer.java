/**
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE
 * file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file
 * to You under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.apache.kafka.common.serialization;

import java.util.Map;

import javax.crypto.Cipher;

/**
 * 
 * This is a serialization wrapper which adds message encryption. Its intended to be used together with {@link DecryptingDeserializer} 
 * <p>
 * This serializer can approx. serialize 1000000/sec messages of 1kb size (benchmarked with Oracle Java 8 and hardware which supports AES-NI instructions)
 * <p>
 * Configuration<p>
 * <ul>
 * <li><em>crypto.rsa.publickey.filepath</em> path on the local filesystem which hold the RSA public key (X.509 format) of the consumer
 * <li><em>crypto.value.serializer</em> is the class or full qualified class name or the wrapped serializer
 * <li><em>crypto.hash.method</em> Type of hash generated for the AES key (optional, default is "adler32"). Possible values are all supported
 * by MessageDigest.getInstance(method). Needs NOT to be cryptographically strong because its only used for caching the key.
 * </ul>
 * 
 * Each message is encrypted with AES before its sent to Kafka. The AES key as well as the initialization vector are random.
 * The AES key is attached to the message in a RSA encrypted manner. The IV is also attached but not RSA encrypted. There is also a hash value
 * of the AES key to allow consumers caching of decrypted AES keys. Finally we have a few magic and header bytes.
 * The resulting byte array looks therefore like this:
 * 
 * <pre>MMLLLHH..HHEEEE..EEEEIIII..IIIOOOOO....OOOOOO</pre>
 * 
 * <ul>
 * <li> MM: Two magic bytes 0xDF 0xBB to detect if this byte sequence is encrypted or not
 * <li> LLL: Three bytes indicating the length of the AES key hash, the RSA encrypted AES key, the IV
 * <li> HH..HH: AES key hash
 * <li> EE..EE: RSA encrypted AES key
 * <li> II..II: Initialization vector
 * <li> OO..OO: The AES encrypted original message
 * </ul>
 * 
 * <em>MMLLL</em> is called the encryption header and consists of 5 bytes.
 * 
 * <ul>
 * <li> M1: 0xDF
 * <li> M2: 0xBB
 * <li> L1: length of the AES key hash
 * <li> L2: RSA factor f so that f*128*8 evaluates to the RSA keysize (in bits)
 * <li> L3: length of the initialization vector in bytes (always 16 for AES)
 * </ul>
 * 
 * RSA public/private keypair can be generated with<br>
 * <em>java org.apache.kafka.common.serialization.SerdeCryptoBase <keysize in bits></em>
 * 
 * <p>
 * <b>Note</b>: As Producers are multithreading-safe this serializer is also thread-safe
 * <p>
 * 
 * @param <T> The type to be serialized from (applied to the wrapped serializer)
 */
public class EncryptingSerializer<T> extends SerdeCryptoBase implements Serializer<T> {

    public static final String CRYPTO_VALUE_SERIALIZER = "crypto.value.serializer";
    private Serializer<T> inner;

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        inner = newInstance(configs, CRYPTO_VALUE_SERIALIZER, Serializer.class);
        inner.configure(configs, isKey);
        init(Cipher.ENCRYPT_MODE, configs, isKey);
    }

    @Override
    public byte[] serialize(String topic, T data) {
        return crypt(inner.serialize(topic, data));
    }

    @Override
    public void close() {
        if (inner != null) {
            inner.close();
        }
    }
    
    public void newKey() {
        super.newKey();
    }
}
