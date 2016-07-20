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

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.utils.Utils;

public abstract class SerdeCryptoBase {

    private static final String AES = "AES";
    private static final String RSA = "RSA";
    public static final String CRYPTO_RSA_PRIVATEKEY_FILEPATH = "crypto.rsa.privatekey.filepath";
    public static final String CRYPTO_RSA_PUBLICKEY_FILEPATH = "crypto.rsa.publickey.filepath";
    public static final String CRYPTO_AES_IV_FILEPATH = "crypto.aes.iv.filepath";
    public static final String CRYPTO_AES_KEY_FILEPATH = "crypto.aes.key.filepath";
    public static final String CRYPTO_TRANSFORMATION = "crypto.transformation";
    protected static final String DEFAULT_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private Cipher cipher;

    protected void init(int opMode, Map<String, ?> configs, boolean isKey) throws KafkaException {
        String transformation = valueOrDefault(configs, CRYPTO_TRANSFORMATION, DEFAULT_TRANSFORMATION);
        String baseAlgorithm = transformation.split("/")[0];

        if (!baseAlgorithm.equals(AES) && !baseAlgorithm.equals(RSA)) {
            throw new KafkaException("Only AES and RSA based transformations are supported by now");
        }

        try {
            cipher = Cipher.getInstance(transformation);

            if (baseAlgorithm.equals(AES)) {
                String aesKeyFile = (String) configs.get(CRYPTO_AES_KEY_FILEPATH);
                String aesIvFile = (String) configs.get(CRYPTO_AES_IV_FILEPATH);
                cipher.init(opMode, createAESSecretKey(readBytesFromFile(aesKeyFile)), new IvParameterSpec(readBytesFromFile(aesIvFile)));
            } else {
                String rsaPublicKeyFile = (String) configs.get(CRYPTO_RSA_PUBLICKEY_FILEPATH);
                String rsaPrivateKeyFile = (String) configs.get(CRYPTO_RSA_PRIVATEKEY_FILEPATH);
                //RSA
                cipher.init(opMode, opMode == Cipher.DECRYPT_MODE ? createRSAPrivateKey(readBytesFromFile(rsaPrivateKeyFile))
                        : createRSAPublicKey(readBytesFromFile(rsaPublicKeyFile)));
            }
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    protected byte[] crypt(byte[] array) throws KafkaException {
        if (cipher == null) {
            throw new KafkaException("Cipher not initialized");
        }

        if (array == null || array.length == 0) {
            return array;
        }

        try {
            return cipher.doFinal(array);
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    @SuppressWarnings("unchecked")
    protected <T> T newInstance(Map<String, ?> map, String key, Class<T> klass) throws KafkaException {
        Object val = map.get(key);
        if (val == null) {
            throw new KafkaException("No value for '" + key + "' found");
        } else if (val instanceof String) {
            try {
                return Utils.newInstance((String) val, klass);
            } catch (ClassNotFoundException e) {
                throw new KafkaException(e);
            }
        } else if (val instanceof Class) {
            return Utils.newInstance((Class<T>) val);
        } else {
            throw new KafkaException("Unexpected type '" + val.getClass() + "' for '" + key + "'");
        }
    }

    private <T> T valueOrDefault(Map<String, ?> map, String key, T defaultValue) {
        return map.containsKey(key) ? (T) map.get(key) : defaultValue;
    }

    private PrivateKey createRSAPrivateKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }
        
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(spec);
    }

    private SecretKey createAESSecretKey(byte[] encodedKey) {
        if(encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }
        
        return new SecretKeySpec(encodedKey, AES);
    }

    private PublicKey createRSAPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }
        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(spec);
    }

    private byte[] readBytesFromFile(String filename) throws IOException {
        if(filename == null) {
            throw new IllegalArgumentException("Filename must not be null");
        }
        
        File f = new File(filename);
        DataInputStream dis = new DataInputStream(new FileInputStream(f));
        byte[] bytes = new byte[(int) f.length()];
        dis.readFully(bytes);
        dis.close();
        return bytes;
    }
}
