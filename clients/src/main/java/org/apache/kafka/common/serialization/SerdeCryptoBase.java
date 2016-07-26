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
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.util.UUID;
import java.util.zip.Adler32;

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

public abstract class SerdeCryptoBase {

    private static final Map<String, byte[]> aesDecryptMap = new HashMap<>();
    private static final byte[] MAGIC_BYTES = new byte[] { (byte) 0xDF, (byte) 0xBB };
    private static final int MAGIC_BYTES_LENGTH = MAGIC_BYTES.length;
    private static final int HEADER_LENGTH = MAGIC_BYTES_LENGTH + 3;
    public static final String CRYPTO_RSA_PRIVATEKEY_FILEPATH = "crypto.rsa.privatekey.filepath";
    public static final String CRYPTO_RSA_PUBLICKEY_FILEPATH = "crypto.rsa.publickey.filepath";
    public static final String CRYPTO_HASH_METHOD = "crypto.hash.method";
    public static final String CRYPTO_IGNORE_DECRYPT_FAILURES = "crypto.ignore_decrypt_failures";
    protected static final String DEFAULT_TRANSFORMATION = "AES/CBC/PKCS5Padding"; //TODO allow other like GCM
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final int RSA_MULTIPLICATOR = 128;
    private int opMode;
    private static String hashMethod = "adler32";
    private static boolean ignoreDecryptFailures = false;
    private ProducerCryptoBundle producerCryptoBundle = null;
    private ConsumerCryptoBundle consumerCryptoBundle = null;
    private final static SecureRandom random;

    static {
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            //should not happen
            throw new KafkaException(e);
        }
    }

    protected SerdeCryptoBase() {
        super();
    }
    
    public static void main(String[] args) throws Exception {
        int keysize = (args != null && args.length > 0) ? Integer.parseInt(args[0]) : 2048;
        System.out.println("Keysize: "+keysize+" bits");
        String uuid = UUID.randomUUID().toString();
        File pubKey = new File("rsa_publickey_" + keysize + "_" + uuid);
        File privKey = new File("rsa_privatekey_" + keysize + "_" + uuid);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
        keyGen.initialize(keysize);
        KeyPair pair = keyGen.genKeyPair();
        byte[] publicKey = pair.getPublic().getEncoded();
        byte[] privateKey = pair.getPrivate().getEncoded();

        FileOutputStream fout = new FileOutputStream(pubKey);
        fout.write(publicKey);
        fout.close();

        fout = new FileOutputStream(privKey);
        fout.write(privateKey);
        fout.close();

        System.out.println(pubKey.getAbsolutePath());
        System.out.println(privKey.getAbsolutePath());
    }

    //not thread safe
    private static class ConsumerCryptoBundle {

        private Cipher rsaDecrypt;
        final Cipher aesDecrypt = Cipher.getInstance(DEFAULT_TRANSFORMATION);

        private ConsumerCryptoBundle(PrivateKey privateKey) throws Exception {
            rsaDecrypt = Cipher.getInstance(RSA);
            rsaDecrypt.init(Cipher.DECRYPT_MODE, privateKey);
        }

        private byte[] aesDecrypt(byte[] encrypted) throws KafkaException {
            try {
                if (encrypted[0] == MAGIC_BYTES[0] && encrypted[1] == MAGIC_BYTES[1]) {
                    final byte hashLen = encrypted[2];
                    final byte rsaFactor = encrypted[3];
                    final byte ivLen = encrypted[4];
                    final int offset = HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR) + ivLen;
                    final String aesHash = Hex.toHexString(Arrays.copyOfRange(encrypted, HEADER_LENGTH, HEADER_LENGTH + hashLen));
                    final byte[] iv = Arrays.copyOfRange(encrypted, HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR),
                            HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR) + ivLen);

                    byte[] aesKey;

                    if ((aesKey = aesDecryptMap.get(aesHash)) != null) {
                        aesDecrypt.init(Cipher.DECRYPT_MODE, createAESSecretKey(aesKey), new IvParameterSpec(iv));
                        return crypt(aesDecrypt, encrypted, offset, encrypted.length - offset);
                    } else {
                        byte[] rsaEncryptedAesKey = Arrays.copyOfRange(encrypted, HEADER_LENGTH + hashLen,
                                HEADER_LENGTH + hashLen + (rsaFactor * RSA_MULTIPLICATOR));
                        aesKey = crypt(rsaDecrypt, rsaEncryptedAesKey);
                        aesDecrypt.init(Cipher.DECRYPT_MODE, createAESSecretKey(aesKey), new IvParameterSpec(iv));
                        aesDecryptMap.put(aesHash, aesKey);
                        return crypt(aesDecrypt, encrypted, offset, encrypted.length - offset);
                    }
                } else {
                    return encrypted; //not encrypted, just bypass decryption
                }
            } catch (Exception e) {
                if(ignoreDecryptFailures) {
                    return encrypted; //Probably not encrypted, just bypass decryption
                }
                
                throw new KafkaException("Decrypt failed",e);
            }
        }
    }

    private static class ThreadAwareKeyInfo {
        private final SecretKey aesKey;
        private final byte[] aesHash;
        private final byte[] rsaEncyptedAesKey;
        private final Cipher rsaCipher;
        private final Cipher aesCipher;

        protected ThreadAwareKeyInfo(PublicKey publicKey) throws Exception {
            byte[] aesKeyBytes = new byte[16];
            random.nextBytes(aesKeyBytes);
            aesCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
            aesKey = createAESSecretKey(aesKeyBytes);
            aesHash = hash(aesKeyBytes);
            rsaCipher = Cipher.getInstance(RSA);
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            rsaEncyptedAesKey = crypt(rsaCipher, aesKeyBytes);
        }
    }

    //threads safe
    private static class ProducerCryptoBundle {

        private ThreadLocal<ThreadAwareKeyInfo> keyInfo = new ThreadLocal<>();
        private final PublicKey publicKey;

        private ProducerCryptoBundle(PublicKey publicKey) throws Exception {
            this.publicKey = publicKey;
        }

        private void newKey() throws Exception {
            final ThreadAwareKeyInfo ki = new ThreadAwareKeyInfo(publicKey);
            keyInfo.set(ki);
        }

        private byte[] aesEncrypt(byte[] plain) throws KafkaException {

            if (keyInfo.get() == null) {
                try {
                    newKey();
                } catch (Exception e) {
                    throw new KafkaException(e);
                }
            }

            final ThreadAwareKeyInfo ki = keyInfo.get();

            try {
                final byte[] aesIv = new byte[16];
                random.nextBytes(aesIv);
                ki.aesCipher.init(Cipher.ENCRYPT_MODE, ki.aesKey, new IvParameterSpec(aesIv));
                final byte[] prolog = Arrays.concatenate(ki.aesHash, ki.rsaEncyptedAesKey, aesIv);
                final byte[] header = Arrays.concatenate(MAGIC_BYTES, new byte[] { (byte) ki.aesHash.length,
                        (byte) (ki.rsaEncyptedAesKey.length / RSA_MULTIPLICATOR), (byte) aesIv.length });
                return Arrays.concatenate(header, prolog, crypt(ki.aesCipher, plain));
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        }
    }

    protected void init(int opMode, Map<String, ?> configs, boolean isKey) throws KafkaException {
        this.opMode = opMode;

        final String hashMethodProperty = (String) configs.get(CRYPTO_HASH_METHOD);
        
        if(hashMethodProperty != null && hashMethodProperty.length() != 0) {
            hashMethod = hashMethodProperty;
        }
        
        final String ignoreDecryptFailuresProperty = (String) configs.get(CRYPTO_IGNORE_DECRYPT_FAILURES);
        
        if(ignoreDecryptFailuresProperty != null && ignoreDecryptFailuresProperty.length() != 0) {
            ignoreDecryptFailures = Boolean.parseBoolean(ignoreDecryptFailuresProperty);
        }
        
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

    /**
     * Generate new AES key for the current thread
     */
    protected void newKey() {
        try {
            producerCryptoBundle.newKey();
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    //Hereafter there are only helper methods

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
            if ("adler32".equalsIgnoreCase(hashMethod)) {
                Adler32 adler = new Adler32();
                adler.update(toHash);
                return longToBytes(adler.getValue());
            } else {
                MessageDigest md = MessageDigest.getInstance(hashMethod);
                md.update(toHash);
                return md.digest();
            }
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }

    private static byte[] longToBytes(long l) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (l & 0xFF);
            l >>= 8;
        }
        return result;
    }

    private static byte[] crypt(Cipher c, byte[] plain) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain);
    }

    private static byte[] crypt(Cipher c, byte[] plain, int offset, int len) throws IllegalBlockSizeException, BadPaddingException {
        return c.doFinal(plain, offset, len);
    }
}
