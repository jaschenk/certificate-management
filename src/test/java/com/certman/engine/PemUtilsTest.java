package com.certman.engine;

import com.certman.domain.KeyAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PemUtils — validates PEM encoding/decoding round-trips
 * for certificates, private keys, and CSRs.
 */
@DisplayName("PemUtils Tests")
class PemUtilsTest {

    private static final KeyPairGenerator keyPairGen = new KeyPairGenerator();
    private static final CertificateBuilder certBuilder = new CertificateBuilder();
    private static final PemUtils pemUtils = new PemUtils();

    @BeforeAll
    static void setup() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("Should round-trip RSA private key through PEM encoding")
    void shouldRoundTripRsaPrivateKey() {
        KeyPair keyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);

        String pem = pemUtils.privateKeyToPem(keyPair.getPrivate());

        assertNotNull(pem, "PEM should not be null");
        assertTrue(pem.contains("PRIVATE KEY"), "PEM should contain PRIVATE KEY header");

        PrivateKey parsed = pemUtils.parsePrivateKey(pem);
        assertNotNull(parsed, "Parsed private key should not be null");
        assertEquals(keyPair.getPrivate().getAlgorithm(), parsed.getAlgorithm(),
                "Parsed key algorithm should match");
        assertArrayEquals(keyPair.getPrivate().getEncoded(), parsed.getEncoded(),
                "Parsed key encoding should match original");
    }

    @Test
    @DisplayName("Should round-trip EC private key through PEM encoding")
    void shouldRoundTripEcPrivateKey() {
        KeyPair keyPair = keyPairGen.generateKeyPair(KeyAlgorithm.EC_P256);

        String pem = pemUtils.privateKeyToPem(keyPair.getPrivate());
        assertNotNull(pem);
        assertTrue(pem.contains("PRIVATE KEY"));

        PrivateKey parsed = pemUtils.parsePrivateKey(pem);
        assertNotNull(parsed);
        assertTrue(parsed.getAlgorithm().equals("EC") || parsed.getAlgorithm().equals("ECDSA"),
                "Expected EC or ECDSA but got: " + parsed.getAlgorithm());
    }

    @Test
    @DisplayName("Should round-trip X.509 certificate through PEM encoding")
    void shouldRoundTripCertificate() throws Exception {
        KeyPair keyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name subject = certBuilder.buildSubjectDn("Test Cert", null, "TestOrg", null, null, "US");

        X509Certificate original = certBuilder.generateRootCaCertificate(
                subject, keyPair, "SHA384withRSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(1),
                -1, null);

        String pem = pemUtils.certificateToPem(original);
        assertNotNull(pem);
        assertTrue(pem.contains("BEGIN CERTIFICATE"), "PEM should contain CERTIFICATE header");

        X509Certificate parsed = pemUtils.parseCertificate(pem);
        assertNotNull(parsed, "Parsed certificate should not be null");
        assertEquals(original.getSerialNumber(), parsed.getSerialNumber(),
                "Serial numbers should match");
        assertEquals(original.getSubjectX500Principal(), parsed.getSubjectX500Principal(),
                "Subject should match");
        assertArrayEquals(original.getEncoded(), parsed.getEncoded(),
                "DER encoding should match");
    }

    @Test
    @DisplayName("Should round-trip PKCS#10 CSR through PEM encoding")
    void shouldRoundTripCsr() {
        KeyPair keyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name subject = certBuilder.buildSubjectDn("test.example.com", null, "Test", null, null, "US");

        PKCS10CertificationRequest original = certBuilder.generateCsr(
                subject, keyPair, "SHA256withRSA");

        String pem = pemUtils.toPem(original);
        assertNotNull(pem);
        assertTrue(pem.contains("CERTIFICATE REQUEST"), "PEM should contain CSR header");

        PKCS10CertificationRequest parsed = pemUtils.parseCsr(pem);
        assertNotNull(parsed, "Parsed CSR should not be null");
        assertEquals(original.getSubject(), parsed.getSubject(),
                "CSR subjects should match");
    }

    @Test
    @DisplayName("Should calculate SHA-256 thumbprint for certificate")
    void shouldCalculateThumbprint() {
        KeyPair keyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name subject = certBuilder.buildSubjectDn("Thumbprint Test", null, "Test", null, null, "US");

        X509Certificate cert = certBuilder.generateRootCaCertificate(
                subject, keyPair, "SHA256withRSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(1),
                -1, null);

        String thumbprint = pemUtils.calculateThumbprint(cert);

        assertNotNull(thumbprint, "Thumbprint should not be null");
        assertEquals(64, thumbprint.length(), "SHA-256 thumbprint should be 64 hex chars");
        assertTrue(thumbprint.matches("[A-F0-9]+"), "Thumbprint should be uppercase hex");

        // Same cert should produce same thumbprint
        String thumbprint2 = pemUtils.calculateThumbprint(cert);
        assertEquals(thumbprint, thumbprint2, "Same cert should produce same thumbprint");
    }

    @Test
    @DisplayName("Should reconstruct KeyPair from PEM private key and certificate")
    void shouldReconstructKeyPair() {
        KeyPair original = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name subject = certBuilder.buildSubjectDn("Reconstruct Test", null, "Test", null, null, "US");

        X509Certificate cert = certBuilder.generateRootCaCertificate(
                subject, original, "SHA384withRSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(1),
                -1, null);

        String keyPem = pemUtils.privateKeyToPem(original.getPrivate());
        String certPem = pemUtils.certificateToPem(cert);

        KeyPair reconstructed = pemUtils.reconstructKeyPair(keyPem, certPem);

        assertNotNull(reconstructed);
        assertEquals(original.getPublic(), reconstructed.getPublic(),
                "Reconstructed public key should match");
        assertArrayEquals(original.getPrivate().getEncoded(), reconstructed.getPrivate().getEncoded(),
                "Reconstructed private key should match");
    }

    @Test
    @DisplayName("Should throw CertificateEngineException for invalid PEM input")
    void shouldThrowOnInvalidPem() {
        assertThrows(CertificateEngineException.class,
                () -> pemUtils.parsePrivateKey("not a valid PEM"),
                "Should throw on invalid private key PEM");

        assertThrows(CertificateEngineException.class,
                () -> pemUtils.parseCertificate("not a valid PEM"),
                "Should throw on invalid certificate PEM");

        assertThrows(CertificateEngineException.class,
                () -> pemUtils.parseCsr("not a valid PEM"),
                "Should throw on invalid CSR PEM");
    }
}