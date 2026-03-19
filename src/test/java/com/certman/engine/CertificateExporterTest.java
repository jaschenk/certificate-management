package com.certman.engine;

import com.certman.domain.CertificateType;
import com.certman.domain.KeyAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CertificateExporter — validates PEM, DER, and PKCS#12 export formats.
 */
@DisplayName("CertificateExporter Tests")
class CertificateExporterTest {

    private static final KeyPairGenerator keyPairGen = new KeyPairGenerator();
    private static final CertificateBuilder certBuilder = new CertificateBuilder();
    private static final CertificateExporter exporter = new CertificateExporter();

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static KeyPair serverKeyPair;
    private static X509Certificate serverCert;

    @BeforeAll
    static void setup() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Create CA
        caKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name caSubject = certBuilder.buildSubjectDn("Export Test CA", null, "TestOrg", null, null, "US");
        caCert = certBuilder.generateRootCaCertificate(
                caSubject, caKeyPair, "SHA384withRSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(10),
                -1, null);

        // Create server cert
        serverKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name serverSubject = certBuilder.buildSubjectDn("export.example.com", null, "Example", null, null, "US");
        serverCert = certBuilder.generateEndEntityCertificate(
                serverSubject, serverKeyPair.getPublic(), caSubject, caKeyPair,
                "SHA384withRSA", BigInteger.TEN,
                LocalDateTime.now(), LocalDateTime.now().plusDays(365),
                CertificateType.SERVER,
                new String[]{"export.example.com"},
                null);
    }

    @Test
    @DisplayName("Should export certificate as PEM")
    void shouldExportCertificateAsPem() {
        String pem = exporter.exportCertificatePem(serverCert);

        assertNotNull(pem);
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"), "PEM should start with BEGIN CERTIFICATE");
        assertTrue(pem.contains("-----END CERTIFICATE-----"), "PEM should end with END CERTIFICATE");
    }

    @Test
    @DisplayName("Should export certificate as DER")
    void shouldExportCertificateAsDer() throws Exception {
        byte[] der = exporter.exportCertificateDer(serverCert);

        assertNotNull(der);
        assertTrue(der.length > 0, "DER should not be empty");
        assertArrayEquals(serverCert.getEncoded(), der,
                "DER export should match certificate encoding");
    }

    @Test
    @DisplayName("Should export PKCS#12 bundle with cert and private key")
    void shouldExportPkcs12Bundle() throws Exception {
        String password = "test1234";
        byte[] p12 = exporter.exportPkcs12(
                serverCert, serverKeyPair.getPrivate(),
                new X509Certificate[]{caCert},
                "server", password);

        assertNotNull(p12);
        assertTrue(p12.length > 0, "PKCS#12 should not be empty");

        // Verify we can load the PKCS#12
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12), password.toCharArray());

        assertTrue(ks.containsAlias("server"), "PKCS#12 should contain 'server' alias");
        assertNotNull(ks.getKey("server", password.toCharArray()),
                "Should be able to retrieve private key from PKCS#12");

        X509Certificate loadedCert = (X509Certificate) ks.getCertificate("server");
        assertNotNull(loadedCert, "Should be able to retrieve certificate from PKCS#12");
        assertEquals(serverCert.getSerialNumber(), loadedCert.getSerialNumber(),
                "Loaded cert serial should match original");

        // Chain should include CA cert
        java.security.cert.Certificate[] chain = ks.getCertificateChain("server");
        assertNotNull(chain);
        assertEquals(2, chain.length, "Chain should contain server cert + CA cert");
    }

    @Test
    @DisplayName("Should export certificate chain as PEM bundle")
    void shouldExportCertificateChainPem() {
        String chainPem = exporter.exportCertificateChainPem(serverCert, caCert);

        assertNotNull(chainPem);
        // Should contain two certificates
        int beginCount = chainPem.split("-----BEGIN CERTIFICATE-----").length - 1;
        assertEquals(2, beginCount, "Chain PEM should contain 2 certificates");
    }

    @Test
    @DisplayName("Should export private key as PEM")
    void shouldExportPrivateKeyPem() {
        String keyPem = exporter.exportPrivateKeyPem(serverKeyPair.getPrivate());

        assertNotNull(keyPem);
        assertTrue(keyPem.contains("PRIVATE KEY"), "PEM should contain PRIVATE KEY header");
    }
}