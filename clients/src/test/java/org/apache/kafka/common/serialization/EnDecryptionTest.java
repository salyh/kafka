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

import org.junit.Test;

import jdk.nashorn.internal.runtime.ECMAException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.Assert.*;

public class EnDecryptionTest {

    final private String topic = "cryptedTestTopic";
    private final File pubKey;
    private final File privKey;
    private final byte[] publicKey;
    private final byte[] privateKey;
    
    public EnDecryptionTest() throws Exception {
        pubKey = File.createTempFile("kafka", "crypto");
        pubKey.deleteOnExit();
        privKey = File.createTempFile("kafka", "crypto");
        privKey.deleteOnExit();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.genKeyPair();
        publicKey = pair.getPublic().getEncoded();
        privateKey = pair.getPrivate().getEncoded();
        
        FileOutputStream fout = new FileOutputStream(pubKey);
        fout.write(publicKey);
        fout.close();
        
        fout = new FileOutputStream(privKey);
        fout.write(privateKey);
        fout.close();
    }
    
    @Test
    public void testEncryptionSerializer() throws IOException, NoSuchAlgorithmException {
        String str = "my string my string my string my string my string";
        
        Map<String, Object> config = new HashMap<>();
        config.put(SerdeCryptoBase.CRYPTO_RSA_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        config.put(SerdeCryptoBase.CRYPTO_RSA_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        config.put(EncryptingSerializer.CRYPTO_VALUE_SERIALIZER, StringSerializer.class.getName());
        config.put(DecryptingDeserializer.CRYPTO_VALUE_DESERIALIZER, StringDeserializer.class);

        EncryptingSerializer<String> serializer = new EncryptingSerializer<String>();
        serializer.configure(config, false);
        Deserializer<String> deserializer = new DecryptingDeserializer<String>();
        deserializer.configure(config, false);

        assertEquals(str, deserializer.deserialize(topic, serializer.serialize(topic, str)));
        assertEquals(null, deserializer.deserialize(topic, serializer.serialize(topic, null)));
        assertEquals(str, deserializer.deserialize(topic, serializer.serialize(topic, str)));
        assertEquals(null, deserializer.deserialize(topic, serializer.serialize(topic, null)));
        
        serializer.newKey();
        
        assertEquals(str, deserializer.deserialize(topic, serializer.serialize(topic, str)));
        assertEquals(null, deserializer.deserialize(topic, serializer.serialize(topic, null)));
        assertEquals(str, deserializer.deserialize(topic, serializer.serialize(topic, str)));
        assertEquals(null, deserializer.deserialize(topic, serializer.serialize(topic, null)));
        
        str = new String(publicKey);
        assertEquals(str, deserializer.deserialize(topic, serializer.serialize(topic, str)));
        
        str = "";
        assertEquals(str, deserializer.deserialize(topic, serializer.serialize(topic, str)));
        
        str = "x";
        assertEquals(str, deserializer.deserialize(topic, serializer.serialize(topic, str)));
        
        str = "unencrypted";
        assertEquals(str, deserializer.deserialize(topic, str.getBytes()));
        
        str = "unencrypted";
        String magic = new String(new byte[] { (byte) 0xDF, (byte) 0xBB });
        assertEquals(magic+str, deserializer.deserialize(topic, (magic+str).getBytes()));
        
        str = "";
        magic = new String(new byte[] { (byte) 0xDF, (byte) 0xBB });
        assertEquals(magic+str, deserializer.deserialize(topic, (magic+str).getBytes()));
        
        str = "unencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencrypted"
             +"unencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencrypted"
             +"unencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencryptedunencrypted";
        magic = new String(new byte[] { (byte) 0xDF, (byte) 0xBB });
        assertEquals(magic+str, deserializer.deserialize(topic, (magic+str).getBytes()));
        
        str = "aaaaaaaaaaaaaaaaaaaaaa";
        magic = new String(new byte[] { (byte) 0xDF, (byte) 0xBB, (byte) 1, (byte) 0, (byte) 1 });
        assertEquals(magic+str, deserializer.deserialize(topic, (magic+str).getBytes()));

    }
    
    @Test
    public void testNonMultithreaded() throws Exception {
        
        final String str = "my string my string my string my string my string";

        final Map<String, Object> config = new HashMap<>();
        config.put(SerdeCryptoBase.CRYPTO_RSA_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        config.put(SerdeCryptoBase.CRYPTO_RSA_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        config.put(EncryptingSerializer.CRYPTO_VALUE_SERIALIZER, StringSerializer.class.getName());
        config.put(DecryptingDeserializer.CRYPTO_VALUE_DESERIALIZER, StringDeserializer.class);

        final EncryptingSerializer<String> serializer = new EncryptingSerializer<String>();
        serializer.configure(config, false);
        final byte[] enc = serializer.serialize(topic, str);
        
        for(int i=0; i<100;i++) {
            Deserializer<String> deserializer0 = new DecryptingDeserializer<String>();
            deserializer0.configure(config, false);
            assertEquals(str, deserializer0.deserialize(topic, enc));
        }
        
        
        
        for(int i=0; i<100;i++) {
            
            final EncryptingSerializer<String> serializer0 = new EncryptingSerializer<String>();
            serializer0.configure(config, false);
            final byte[] enc2 = serializer0.serialize(topic, str);
            
            
            Deserializer<String> deserializer0 = new DecryptingDeserializer<String>();
            deserializer0.configure(config, false);
            assertEquals(str, deserializer0.deserialize(topic, enc2));
        }
        
    }
    
    @Test
    public void testMultithreaded() throws Exception {
        final String str = "my string my string my string my string my string";

        final Map<String, Object> config = new HashMap<>();
        config.put(SerdeCryptoBase.CRYPTO_RSA_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        config.put(SerdeCryptoBase.CRYPTO_RSA_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        config.put(EncryptingSerializer.CRYPTO_VALUE_SERIALIZER, StringSerializer.class.getName());
        config.put(DecryptingDeserializer.CRYPTO_VALUE_DESERIALIZER, StringDeserializer.class);

        final EncryptingSerializer<String> serializer = new EncryptingSerializer<String>();
        serializer.configure(config, false);
        
        final ExecutorService es = Executors.newFixedThreadPool(100);
        final List<Future<Exception>> futures = new ArrayList<>();
        
        for(int i=0; i<100;i++) {
            Future<Exception> f = es.submit(new Callable<Exception>() {
                
                @Override
                public Exception call() throws Exception {
                    try {
                        final byte[] enc = serializer.serialize(topic, str);
                        final Deserializer<String> deserializer = new DecryptingDeserializer<String>();
                        deserializer.configure(config, false);
                        assertEquals(str, deserializer.deserialize(topic, enc));
                        return null;
                    } catch (Exception e) {
                        return e;
                    }
                    
                }
                
            });
            futures.add(f);
        }

        for(Future<Exception> f: futures) {
            Exception e = f.get();
            if(e != null) {
                throw e;
            }
        }
    }
}
