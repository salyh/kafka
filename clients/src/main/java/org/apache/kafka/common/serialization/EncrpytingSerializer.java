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

public class EncrpytingSerializer<T> extends SerdeCryptoBase implements Serializer<T> {

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
