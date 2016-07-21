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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.utils.Utils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

//TODO need to make at least the producer/serializer code multithreading safe
public abstract class SerdeCryptoBase {

    private static final Map<String, byte[]> aesDecryptMap = new HashMap<>(); //TODO check thread safeness
    private static final byte[] MAGIC_BYTES = new byte[] { (byte) 0xDF, (byte) 0xBB };
    private static final int MAGIC_BYTES_LENGTH = MAGIC_BYTES.length;
    private static final int HEADER_LENGTH = MAGIC_BYTES_LENGTH+3;
    public static final String CRYPTO_RSA_PRIVATEKEY_FILEPATH = "crypto.rsa.privatekey.filepath";
    public static final String CRYPTO_RSA_PUBLICKEY_FILEPATH = "crypto.rsa.publickey.filepath";
    protected static final String DEFAULT_TRANSFORMATION = "AES/CBC/PKCS5Padding"; //TODO allow other like GCM
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private int opMode;
    private ProducerCryptoBundle producerCryptoBundle = null;
    private ConsumerCryptoBundle consumerCryptoBundle = null;
    
    protected SerdeCryptoBase() {
        super();
    }

    private static class ConsumerCryptoBundle {

        private Cipher rsaDecrypt;

        private ConsumerCryptoBundle(PrivateKey privateKey) throws Exception {
            rsaDecrypt = Cipher.getInstance(RSA);
            rsaDecrypt.init(Cipher.DECRYPT_MODE, privateKey);
        }

        private byte[] aesDecrypt(byte[] encrypted) throws KafkaException {
            try {
                if (encrypted[0] == MAGIC_BYTES[0] && encrypted[1] == MAGIC_BYTES[1]) {
                    byte hashLen = encrypted[2];
                    byte rsaFactor = encrypted[3];
                    byte ivLen = encrypted[4];
                    int offset = HEADER_LENGTH+hashLen+(rsaFactor*128)+ivLen;
                    byte[] aesHash = Arrays.copyOfRange(encrypted, HEADER_LENGTH, HEADER_LENGTH+hashLen);
                    byte[] iv = Arrays.copyOfRange(encrypted, HEADER_LENGTH+hashLen+(rsaFactor*128), HEADER_LENGTH+hashLen+(rsaFactor*128)+ivLen);

                    byte[] aesKey;

                    if ((aesKey = aesDecryptMap.get(Hex.toHexString(aesHash))) != null) {
                        Cipher aesDecrypt = Cipher.getInstance(DEFAULT_TRANSFORMATION);
                        aesDecrypt.init(Cipher.DECRYPT_MODE, createAESSecretKey(aesKey), new IvParameterSpec(iv));
                        return crypt(aesDecrypt, encrypted, offset, encrypted.length - offset);
                    } else {
                        byte[] rsaEncryptedAesKey = Arrays.copyOfRange(encrypted, HEADER_LENGTH+hashLen, HEADER_LENGTH+hashLen+(rsaFactor*128));
                        aesKey = crypt(rsaDecrypt, rsaEncryptedAesKey);
                        Cipher aesDecrypt = Cipher.getInstance(DEFAULT_TRANSFORMATION);
                        aesDecrypt.init(Cipher.DECRYPT_MODE, createAESSecretKey(aesKey), new IvParameterSpec(iv));
                        aesDecryptMap.put(Hex.toHexString(aesHash), aesKey);
                        return crypt(aesDecrypt, encrypted, offset, encrypted.length - offset);
                    }
                } else {
                    return encrypted; //not encrypted, just bypass decryption
                }
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        }
    }

    private static class ProducerCryptoBundle {

        private volatile SecretKey aesKey;
        private volatile byte[] aesHash;
        private volatile byte[] rsaEncyptedAesKey;
        private final Cipher rsa;
        private final Cipher aesEncrypt;
        private final SecureRandom random = SecureRandom.getInstanceStrong();

        //Producer
        private ProducerCryptoBundle(PublicKey publicKey) throws Exception {
            aesEncrypt = Cipher.getInstance(DEFAULT_TRANSFORMATION);
            rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            newKey();
        }

        //TODO check thread safeness
        private void newKey() throws Exception {
            byte[] aesKeyBytes = new byte[16];
            random.nextBytes(aesKeyBytes);
            aesKey = createAESSecretKey(aesKeyBytes);
            aesHash = hash(aesKeyBytes);
            rsaEncyptedAesKey = crypt(rsa, aesKeyBytes);
        }

        private byte[] aesEncrypt(byte[] plain) throws KafkaException {
            try {
                byte[] aesIv = new byte[16];
                random.nextBytes(aesIv);
                aesEncrypt.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(aesIv));
                byte[] prolog = Arrays.concatenate(aesHash, rsaEncyptedAesKey, aesIv);
                byte[] header = Arrays.concatenate(MAGIC_BYTES, new byte[]{(byte)aesHash.length, (byte)(rsaEncyptedAesKey.length/128),(byte)aesIv.length});
                return Arrays.concatenate(header, prolog, crypt(aesEncrypt, plain));
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        }
    }
    

    protected void init(int opMode, Map<String, ?> configs, boolean isKey) throws KafkaException {
        this.opMode = opMode;
        
        try {
            if (opMode == Cipher.DECRYPT_MODE) {
                //Consumer
                String rsaPrivateKeyFile = (String) configs.get(CRYPTO_RSA_PRIVATEKEY_FILEPATH);
                consumerCryptoBundle = new ConsumerCryptoBundle(createRSAPrivateKey(readBytesFromFile(rsaPrivateKeyFile)));
            } else {
                //Producer
                String rsaPublicKeyFile = (String) configs.get(CRYPTO_RSA_PUBLICKEY_FILEPATH);
                producerCryptoBundle = new ProducerCryptoBundle(createRSAPublicKey(readBytesFromFile(rsaPublicKeyFile)));
            }
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    protected byte[] crypt(byte[] array) throws KafkaException {
        if (array == null || array.length == 0) {
            return array;
        }

        if (opMode == Cipher.DECRYPT_MODE) {
            //Consumer
            return consumerCryptoBundle.aesDecrypt(array);
        } else {
            //Producer
            return producerCryptoBundle.aesEncrypt(array);
        }
    }
    
    protected void newKey() {
        try {
            producerCryptoBundle.newKey();
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

    private static PrivateKey createRSAPrivateKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(spec);
    }

    private static SecretKey createAESSecretKey(byte[] encodedKey) {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        return new SecretKeySpec(encodedKey, AES);
    }

    private static PublicKey createRSAPublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(spec);
    }

    private static byte[] readBytesFromFile(String filename) throws IOException {
        if (filename == null) {
            throw new IllegalArgumentException("Filename must not be null");
        }

        File f = new File(filename);
        DataInputStream dis = new DataInputStream(new FileInputStream(f));
        byte[] bytes = new byte[(int) f.length()];
        dis.readFully(bytes);
        dis.close();
        return bytes;
    }

    private static byte[] hash(byte[] toHash) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(toHash);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new KafkaException(e);
        }
    }

    private static byte[] crypt(Cipher c, byte[] plain) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain);
    }

    private static byte[] crypt(Cipher c, byte[] plain, int offset, int len) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain, offset, len);
    }
}
