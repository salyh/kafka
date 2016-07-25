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
 * This is a deserialization (for the Consumer) wrapper which adds transparent end-to-end message encryption. 
 * Its intended to be used together with {@link EncryptingSerializer} 
 * 
 * 
 * Configuration<p>
 * <ul>
 * <li><em>crypto.rsa.privatekey.filepath</em> path on the local filesystem which hold the RSA private key of the consumer
 * <li><em>crypto.value.deserializer</em> is the class or full qualified class name or the wrapped deserializer
 * </ul>
 * 
 * See {@link EncryptingSerializer} on how encryption works
 * 
 * This class will auto detect if an incoming message is encrypted. If not then no decryption attempt is made and message gets handled normally.
 * <p>
 * <b>Note</b>: As Consumers are not multithreading-safe this deserializer is also not thread-safe
 * <p>
 * @param <T> The type to be deserialized from (applied to the wrapped deserializer)
 */
public class DecryptingDeserializer<T> extends SerdeCryptoBase implements Deserializer<T> {

    public static final String CRYPTO_VALUE_DESERIALIZER = "crypto.value.deserializer";
    private Deserializer<T> inner;

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        inner = newInstance(configs, CRYPTO_VALUE_DESERIALIZER, Deserializer.class);
        inner.configure(configs, isKey);
        init(Cipher.DECRYPT_MODE, configs, isKey);
    }

    @Override
    public T deserialize(String topic, byte[] data) {
        return inner.deserialize(topic, crypt(data));
    }

    @Override
    public void close() {
        if (inner != null) {
            inner.close();
        }
    }
}
