/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.common.security.ssl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.config.types.Password;
import org.apache.kafka.common.network.Mode;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

public class SslFactory implements Configurable {

    private final Mode mode;
    private final String clientAuthConfigOverride;

    private SecurityStore keystore = null;
    private SecurityStore truststore;
    private String[] cipherSuites;
    private String[] enabledProtocols;
    private String endpointIdentification;
    private SslContext sslContext;
    private boolean needClientAuth;
    private boolean wantClientAuth;
    private final SslProvider sslProvider = OpenSsl.isAvailable()?SslProvider.OPENSSL:SslProvider.JDK;

    public SslFactory(Mode mode) {
        this(mode, null);
    }

    public SslFactory(Mode mode, String clientAuthConfigOverride) {
        this.mode = mode;
        this.clientAuthConfigOverride = clientAuthConfigOverride;
    }

    @Override
    public void configure(Map<String, ?> configs) throws KafkaException {

        @SuppressWarnings("unchecked")
        List<String> cipherSuitesList = (List<String>) configs.get(SslConfigs.SSL_CIPHER_SUITES_CONFIG);
        if (cipherSuitesList != null)
            this.cipherSuites = cipherSuitesList.toArray(new String[cipherSuitesList.size()]);

        @SuppressWarnings("unchecked")
        List<String> enabledProtocolsList = (List<String>) configs.get(SslConfigs.SSL_ENABLED_PROTOCOLS_CONFIG);
        if (enabledProtocolsList != null)
            this.enabledProtocols = enabledProtocolsList.toArray(new String[enabledProtocolsList.size()]);

        String endpointIdentification = (String) configs.get(SslConfigs.SSL_ENDPOINT_IDENTIFICATION_ALGORITHM_CONFIG);
        if (endpointIdentification != null)
            this.endpointIdentification = endpointIdentification;

        String clientAuthConfig = clientAuthConfigOverride;
        if (clientAuthConfig == null)
            clientAuthConfig = (String) configs.get(SslConfigs.SSL_CLIENT_AUTH_CONFIG);
        if (clientAuthConfig != null) {
            if (clientAuthConfig.equals("required"))
                this.needClientAuth = true;
            else if (clientAuthConfig.equals("requested"))
                this.wantClientAuth = true;
        }

        createKeystore((String) configs.get(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG),
                       (String) configs.get(SslConfigs.SSL_KEYSTORE_LOCATION_CONFIG),
                       (Password) configs.get(SslConfigs.SSL_KEYSTORE_PASSWORD_CONFIG),
                       (Password) configs.get(SslConfigs.SSL_KEY_PASSWORD_CONFIG));

        createTruststore((String) configs.get(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG),
                         (String) configs.get(SslConfigs.SSL_TRUSTSTORE_LOCATION_CONFIG),
                         (Password) configs.get(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG));
        try {
            this.sslContext = createSSLContext();
        } catch (Exception e) {
            throw new KafkaException(e);
        }
    }


    private SslContext createSSLContext() throws GeneralSecurityException, IOException  {
        
        //TODO keystore and truststore handling is strange here
        //Its now setup it that way that the unit tests work but this needs rework
        
        if(mode == Mode.CLIENT) {
            SslContextBuilder ctxBuilder = SslContextBuilder
                    .forClient()
                    .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                    .sslProvider(sslProvider)
                    .trustManager(truststore.getCertificateChain());
            
            if(keystore != null) {
                    //should the client send also certificates to the server for mutual/two way SSL?
                    ctxBuilder.keyManager(keystore.getDecryptedKey(), keystore.getCertificateChain());
            }
                    
            return ctxBuilder.build();
        } else {
            SslContextBuilder ctxBuilder = SslContextBuilder
                     //keystore should contain the private key as well as the certificate chain for the server
                     //Its now setup it that way that the unit tests work but this needs rework
                    .forServer(keystore.getDecryptedKey(), truststore.getCertificateChain())
                    .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                    .sslProvider(sslProvider)
                    
                    //that neccessary if the client send certificates to prove identity
                    //check that this certificates are trusted
                    .trustManager(truststore.getCertificateChain());
            
            return ctxBuilder.build();
        }
    }

    public SSLEngine createSslEngine(String peerHost, int peerPort) {
        SSLEngine sslEngine = sslContext.newEngine(PooledByteBufAllocator.DEFAULT, peerHost, peerPort);
        if (cipherSuites != null) sslEngine.setEnabledCipherSuites(cipherSuites);
        if (enabledProtocols != null) sslEngine.setEnabledProtocols(enabledProtocols);

        if (mode == Mode.SERVER) {
            sslEngine.setUseClientMode(false);
            if (needClientAuth)
                sslEngine.setNeedClientAuth(needClientAuth);
            else
                sslEngine.setWantClientAuth(wantClientAuth);
        } else {
            sslEngine.setUseClientMode(true);
            SSLParameters sslParams = sslEngine.getSSLParameters();
            sslParams.setEndpointIdentificationAlgorithm(endpointIdentification);
            sslEngine.setSSLParameters(sslParams);
        }
        return sslEngine;
    }

    //TODO figure out how we can create a SSL Server Socket for the Echo server
    ///**
    // * Returns a configured SSLContext.
    // * @return SSLContext.
    // */
    //public SslContext sslContext() {
    //    return sslContext;
    //}
    
    

    private void createKeystore(String type, String path, Password password, Password keyPassword) {
        if (path == null && password != null) {
            throw new KafkaException("SSL key store is not specified, but key store password is specified.");
        } else if (path != null && password == null) {
            throw new KafkaException("SSL key store is specified, but key store password is not specified.");
        } else if (path != null && password != null) {
            this.keystore = new SecurityStore(type, path, password, keyPassword);
        }
    }

    private void createTruststore(String type, String path, Password password) {
        if (path == null && password != null) {
            throw new KafkaException("SSL trust store is not specified, but trust store password is specified.");
        } else if (path != null && password == null) {
            throw new KafkaException("SSL trust store is specified, but trust store password is not specified.");
        } else if (path != null && password != null) {
            this.truststore = new SecurityStore(type, path, password, null);
        }
    }

    private class SecurityStore {
        private final String type;
        private final String path;
        private final Password storePassword;
        private Key key;
        private X509Certificate[] certs;

        private SecurityStore(String type, String path, Password storePassword, Password keyPassword) {
            this.type = type == null ? KeyStore.getDefaultType() : type;
            this.path = path;
            this.storePassword = storePassword;

            try {
                KeyStore store = load();
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();

                    if (store.isKeyEntry(alias) && key == null) {
                        //We just take the first key we find
                        //TODO introduce 'alias' as configuration option here
                        key = store.getKey(alias, keyPassword.value().toCharArray());
                    } else if (certs == null) {
                         //We just take the first certificate or certificate chain we find
                        //TODO introduce 'alias' as configuration option here
                        
                        Certificate cert = store.getCertificate(alias);
                        if (cert == null) {
                            Certificate[] _certs = store.getCertificateChain(alias);
                            List<X509Certificate> c = new ArrayList<>();

                            for (int i = 0; i < _certs.length; i++) {
                                Certificate certificate = _certs[i];
                                c.add((X509Certificate) certificate);
                            }

                            this.certs = c.toArray(new X509Certificate[0]);
                        } else {
                            this.certs = new X509Certificate[] { (X509Certificate) cert };
                        }
                    }
                }
            } catch (Exception e) {
                throw new KafkaException(e);
            }
        }
        
        //TODO getCertificateChain(String alias)
        private X509Certificate[] getCertificateChain() {
            return this.certs;
        }
        
        //TODO getDecryptedKey(String alias)
        private PrivateKey getDecryptedKey() {
            return (PrivateKey) key;
        }

        private KeyStore load() throws GeneralSecurityException, IOException {
            FileInputStream in = null;
            try {
                KeyStore ks = KeyStore.getInstance(type);
                in = new FileInputStream(path);
                ks.load(in, storePassword.value().toCharArray());
                return ks;
            } finally {
                if (in != null) in.close();
            }
        }
    }

}
