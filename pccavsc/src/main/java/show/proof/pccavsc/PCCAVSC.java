package show.proof.pccavsc;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class PCCAVSC {
    private String keyTag;
    private KeyStore keyStore;
    private KeyPair keyPair;

    public PCCAVSC() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException, IOException {
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyTag = UUID.randomUUID().toString();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        keyTag,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512, KeyProperties.DIGEST_NONE)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .build());
        keyPair = keyPairGenerator.generateKeyPair();
    }

    protected void finalize() {
        // try to remove key
        try {
            keyStore.deleteEntry(keyTag);
        } catch (KeyStoreException e) {
        }
    }

    public void removeKey() {
        try {
            keyStore.deleteEntry(keyTag);
        } catch (KeyStoreException e) {
        }
    }

    /*
     Get CSR by email address
    */
    public String getCSR(String emailAddress) {
        try {
            String principal = String.format("CN=%s", emailAddress);
            ContentSigner signer = new JCESigner(keyPair.getPrivate(), "SHA256withRSA");

            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(principal), keyPair.getPublic());
            StringWriter stringWriter = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(stringWriter);
            pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csrBuilder.build(signer).getEncoded()));
            pemWriter.flush();
            stringWriter.flush();
            return stringWriter.toString();
        } catch (Exception exErr) {
            return null;
        }
    }

    public String getCert(String csr) {
        try {
            String cert;
            URL url = new URL("https://proof.show/api/v1/cert");
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            try {
                InputStream in = new BufferedInputStream(urlConnection.getInputStream());
                cert = readStream(in);
            } finally {
                urlConnection.disconnect();
            }
            return cert;
        } catch (Exception exErr) {
            return null;
        }

    }
    public byte[] getSignedHash(byte[] hash) {
        Signature signature;
        try {
            signature = Signature.getInstance("NONEwithRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(hash);
            return signature.sign();
        } catch (Exception e) {
            return null;
        }
    }

    private String readStream(InputStream is) {
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            int i = is.read();
            while(i != -1) {
                bo.write(i);
                i = is.read();
            }
            return bo.toString();
        } catch (IOException e) {
            return "";
        }
    }
    private static class JCESigner implements ContentSigner {

        private static Map<String, AlgorithmIdentifier> ALGOS = new HashMap<String, AlgorithmIdentifier>();

        static {
            ALGOS.put("SHA256withRSA".toLowerCase(), new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
            ALGOS.put("SHA1withRSA".toLowerCase(), new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier("1.2.840.113549.1.1.5")));

        }

        private String mAlgo;
        private Signature signature;
        private ByteArrayOutputStream outputStream;

        public JCESigner(PrivateKey privateKey, String sigAlgo) {
            //Utils.throwIfNull(privateKey, sigAlgo);
            mAlgo = sigAlgo.toLowerCase();
            try {
                this.outputStream = new ByteArrayOutputStream();
                this.signature = Signature.getInstance(sigAlgo);
                this.signature.initSign(privateKey);
            } catch (GeneralSecurityException gse) {
                throw new IllegalArgumentException(gse.getMessage());
            }
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            AlgorithmIdentifier id = ALGOS.get(mAlgo);
            if (id == null) {
                throw new IllegalArgumentException("Does not support algo: " +
                        mAlgo);
            }
            return id;
        }

        @Override
        public OutputStream getOutputStream() {
            return outputStream;
        }

        @Override
        public byte[] getSignature() {
            try {
                signature.update(outputStream.toByteArray());
                return signature.sign();
            } catch (GeneralSecurityException gse) {
                gse.printStackTrace();
                return null;
            }
        }
    }


}
