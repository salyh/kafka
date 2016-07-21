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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class SerializationTest {

    final private String topic = "testTopic";

    private class DummyClass {

    }

    @Test
    public void testSerdeFrom() {
        Serde<Long> thisSerde = Serdes.serdeFrom(Long.class);
        Serde<Long> otherSerde = Serdes.Long();

        Long value = 423412424L;

        assertEquals("Should get the original long after serialization and deserialization",
                value, thisSerde.deserializer().deserialize(topic, otherSerde.serializer().serialize(topic, value)));
        assertEquals("Should get the original long after serialization and deserialization",
                value, otherSerde.deserializer().deserialize(topic, thisSerde.serializer().serialize(topic, value)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSerdeFromUnknown() {
        Serdes.serdeFrom(DummyClass.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSerdeFromNotNull() {
        Serdes.serdeFrom(null, Serdes.Long().deserializer());
    }

    @Test
    public void testStringSerializer() {
        String str = "my string";

        List<String> encodings = new ArrayList<String>();
        encodings.add("UTF8");
        encodings.add("UTF-16");

        for (String encoding : encodings) {
            Serde<String> serDeser = getStringSerde(encoding);
            Serializer<String> serializer = serDeser.serializer();
            Deserializer<String> deserializer = serDeser.deserializer();

            assertEquals("Should get the original string after serialization and deserialization with encoding " + encoding,
                    str, deserializer.deserialize(topic, serializer.serialize(topic, str)));

            assertEquals("Should support null in serialization and deserialization with encoding " + encoding,
                    null, deserializer.deserialize(topic, serializer.serialize(topic, null)));
        }
    }
    
    @Test
    public void testEncryptionSerializer() throws IOException, NoSuchAlgorithmException {
        String str = "my string my string my string my string my string";

        File pubKey = File.createTempFile("kafka", "crypto");
        pubKey.deleteOnExit();
        File privKey = File.createTempFile("kafka", "crypto");
        privKey.deleteOnExit();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024*2);
        KeyPair pair = keyGen.genKeyPair();
        byte[] publicKey = pair.getPublic().getEncoded();
        byte[] privateKey = pair.getPrivate().getEncoded();
        
        FileOutputStream fout = new FileOutputStream(pubKey);
        fout.write(publicKey);
        fout.close();
        
        fout = new FileOutputStream(privKey);
        fout.write(privateKey);
        fout.close();
        
        Map<String, Object> config = new HashMap<>();
        config.put(SerdeCryptoBase.CRYPTO_RSA_PRIVATEKEY_FILEPATH, privKey.getAbsolutePath());
        config.put(SerdeCryptoBase.CRYPTO_RSA_PUBLICKEY_FILEPATH, pubKey.getAbsolutePath());
        config.put(EncrpytingSerializer.CRYPTO_VALUE_SERIALIZER, StringSerializer.class.getName());
        config.put(DecryptingDeserializer.CRYPTO_VALUE_DESERIALIZER, StringDeserializer.class);

        EncrpytingSerializer<String> serializer = new EncrpytingSerializer<String>();
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
        assertEquals(str, deserializer.deserialize(topic, new StringSerializer().serialize(topic, str)));

    }

    @Test
    public void testIntegerSerializer() {
        Integer[] integers = new Integer[]{
            423412424,
            -41243432
        };

        Serializer<Integer> serializer = Serdes.Integer().serializer();
        Deserializer<Integer> deserializer = Serdes.Integer().deserializer();

        for (Integer integer : integers) {
            assertEquals("Should get the original integer after serialization and deserialization",
                    integer, deserializer.deserialize(topic, serializer.serialize(topic, integer)));
        }

        assertEquals("Should support null in serialization and deserialization",
                null, deserializer.deserialize(topic, serializer.serialize(topic, null)));

        serializer.close();
        deserializer.close();
    }

    @Test
    public void testLongSerializer() {
        Long[] longs = new Long[]{
            922337203685477580L,
            -922337203685477581L
        };

        Serializer<Long> serializer = Serdes.Long().serializer();
        Deserializer<Long> deserializer = Serdes.Long().deserializer();

        for (Long value : longs) {
            assertEquals("Should get the original long after serialization and deserialization",
                    value, deserializer.deserialize(topic, serializer.serialize(topic, value)));
        }

        assertEquals("Should support null in serialization and deserialization",
                null, deserializer.deserialize(topic, serializer.serialize(topic, null)));

        serializer.close();
        deserializer.close();
    }

    @Test
    public void testDoubleSerializer() {
        Double[] doubles = new Double[]{
            5678567.12312d,
            -5678567.12341d
        };

        Serializer<Double> serializer = Serdes.Double().serializer();
        Deserializer<Double> deserializer = Serdes.Double().deserializer();

        for (Double value : doubles) {
            assertEquals("Should get the original double after serialization and deserialization",
                    value, deserializer.deserialize(topic, serializer.serialize(topic, value)));
        }

        assertEquals("Should support null in serialization and deserialization",
                null, deserializer.deserialize(topic, serializer.serialize(topic, null)));

        serializer.close();
        deserializer.close();
    }

    @Test
    public void testByteBufferSerializer() {
        ByteBuffer buf = ByteBuffer.allocate(10);
        buf.put("my string".getBytes());

        Serializer<ByteBuffer> serializer = Serdes.ByteBuffer().serializer();
        Deserializer<ByteBuffer> deserializer = Serdes.ByteBuffer().deserializer();

        assertEquals("Should get the original ByteBuffer after serialization and deserialization",
              buf, deserializer.deserialize(topic, serializer.serialize(topic, buf)));

        assertEquals("Should support null in serialization and deserialization",
                null, deserializer.deserialize(topic, serializer.serialize(topic, null)));

        serializer.close();
        deserializer.close();
    }

    private Serde<String> getStringSerde(String encoder) {
        Map<String, Object> serializerConfigs = new HashMap<String, Object>();
        serializerConfigs.put("key.serializer.encoding", encoder);
        Serializer<String> serializer = Serdes.String().serializer();
        serializer.configure(serializerConfigs, true);

        Map<String, Object> deserializerConfigs = new HashMap<String, Object>();
        deserializerConfigs.put("key.deserializer.encoding", encoder);
        Deserializer<String> deserializer = Serdes.String().deserializer();
        deserializer.configure(deserializerConfigs, true);

        return Serdes.serdeFrom(serializer, deserializer);
    }
}
