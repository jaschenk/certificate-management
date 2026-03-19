package com.certman.engine;

import com.certman.domain.CertificateType;
import com.certman.domain.KeyAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CertificateBuilder — validates X.509 certificate creation,
 * CSR generation, and CSR signing per RFC 5280 / RFC 2986.
 */
@DisplayName("CertificateBuilder Tests")
class CertificateBuilderTest {

    private static final KeyPairGenerator keyPairGen = new KeyPairGenerator();
    private static final CertificateBuilder builder = new CertificateBuilder();

    @BeforeAll
    static void setup() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("Should build valid X.500 distinguished name")
    void shouldBuildSubjectDn() {
        X500Name dn = builder.buildSubjectDn("Test CA", "IT", "TestOrg", "NYC", "NY", "US");

        assertNotNull(dn);
        String dnStr = dn.toString();
        assertTrue(dnStr.contains("CN=Test CA"), "DN should contain CN");
        assertTrue(dnStr.contains("O=TestOrg"), "DN should contain O");
        assertTrue(dnStr.contains("C=US"), "DN should contain C");
    }

    @Test
    @DisplayName("Should generate a valid self-signed Root CA certificate")
    void shouldGenerateRootCaCertificate() throws Exception {
        KeyPair keyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name subject = builder.buildSubjectDn("Test Root CA", null, "TestOrg", null, null, "US");

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusYears(10);

        X509Certificate cert = builder.generateRootCaCertificate(
                subject, keyPair, "SHA384withRSA",
                BigInteger.ONE, notBefore, notAfter,
                -1, null);

        assertNotNull(cert, "Certificate should not be null");

        // Self-signed: issuer == subject
        assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal(),
                "Root CA should be self-signed (issuer == subject)");

        // Basic Constraints: CA=true
        assertTrue(cert.getBasicConstraints() >= 0,
                "Root CA should have BasicConstraints with CA=true");

        // Verify signature
        assertDoesNotThrow(() -> cert.verify(keyPair.getPublic()),
                "Certificate signature should be valid");

        // Key Usage
        boolean[] keyUsage = cert.getKeyUsage();
        assertNotNull(keyUsage, "Key usage should not be null");
        assertTrue(keyUsage[5], "keyCertSign should be set for CA");
        assertTrue(keyUsage[6], "cRLSign should be set for CA");
    }

    @Test
    @DisplayName("Should generate Intermediate CA signed by Root CA")
    void shouldGenerateIntermediateCaCertificate() throws Exception {
        // Create Root CA
        KeyPair rootKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name rootSubject = builder.buildSubjectDn("Root CA", null, "TestOrg", null, null, "US");
        X509Certificate rootCert = builder.generateRootCaCertificate(
                rootSubject, rootKeyPair, "SHA384withRSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(10),
                -1, null);

        // Create Intermediate CA
        KeyPair intKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name intSubject = builder.buildSubjectDn("Intermediate CA", null, "TestOrg", null, null, "US");

        X509Certificate intCert = builder.generateIntermediateCaCertificate(
                intSubject, intKeyPair.getPublic(), rootSubject, rootKeyPair,
                "SHA384withRSA", BigInteger.TWO,
                LocalDateTime.now(), LocalDateTime.now().plusYears(5),
                0, null);

        assertNotNull(intCert, "Intermediate CA cert should not be null");

        // Signed by Root
        assertDoesNotThrow(() -> intCert.verify(rootKeyPair.getPublic()),
                "Intermediate cert should be verifiable with Root CA public key");

        // Not self-signed
        assertNotEquals(intCert.getSubjectX500Principal(), intCert.getIssuerX500Principal(),
                "Intermediate CA should not be self-signed");

        // CA constraint
        assertTrue(intCert.getBasicConstraints() >= 0,
                "Intermediate CA should have BasicConstraints CA=true");
    }

    @Test
    @DisplayName("Should generate end-entity TLS server certificate")
    void shouldGenerateServerCertificate() throws Exception {
        // Create CA
        KeyPair caKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name caSubject = builder.buildSubjectDn("Test CA", null, "TestOrg", null, null, "US");
        builder.generateRootCaCertificate(
                caSubject, caKeyPair, "SHA384withRSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(10),
                -1, null);

        // Create server cert
        KeyPair serverKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name serverSubject = builder.buildSubjectDn("www.example.com", null, "Example Inc", null, null, "US");

        X509Certificate serverCert = builder.generateEndEntityCertificate(
                serverSubject, serverKeyPair.getPublic(), caSubject, caKeyPair,
                "SHA384withRSA", BigInteger.TEN,
                LocalDateTime.now(), LocalDateTime.now().plusDays(365),
                CertificateType.SERVER,
                new String[]{"www.example.com", "api.example.com", "192.168.1.1"},
                null);

        assertNotNull(serverCert, "Server cert should not be null");

        // Not a CA
        assertEquals(-1, serverCert.getBasicConstraints(),
                "End-entity cert should have BasicConstraints CA=false");

        // Signed by CA
        assertDoesNotThrow(() -> serverCert.verify(caKeyPair.getPublic()),
                "Server cert should be verifiable with CA public key");

        // Check EKU
        assertNotNull(serverCert.getExtendedKeyUsage(), "EKU should not be null");
        assertTrue(serverCert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.1"),
                "Server cert should have serverAuth EKU");
    }

    @Test
    @DisplayName("Should generate PKCS#10 CSR and sign it into a certificate")
    void shouldGenerateAndSignCsr() throws Exception {
        // Create CA
        KeyPair caKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_4096);
        X500Name caSubject = builder.buildSubjectDn("Test CA", null, "TestOrg", null, null, "US");
        builder.generateRootCaCertificate(
                caSubject, caKeyPair, "SHA384withRSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(10),
                -1, null);

        // Generate CSR
        KeyPair csrKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name csrSubject = builder.buildSubjectDn("app.example.com", null, "Example", null, null, "US");

        PKCS10CertificationRequest csr = builder.generateCsr(
                csrSubject, csrKeyPair, "SHA256withRSA");

        assertNotNull(csr, "CSR should not be null");
        assertEquals(csrSubject, csr.getSubject(), "CSR subject should match");

        // Sign the CSR
        X509Certificate signedCert = builder.signCsr(
                csr, caSubject, caKeyPair, "SHA384withRSA",
                BigInteger.valueOf(100),
                LocalDateTime.now(), LocalDateTime.now().plusDays(365),
                CertificateType.SERVER,
                new String[]{"app.example.com"},
                null);

        assertNotNull(signedCert, "Signed cert should not be null");

        // Verify certificate was signed by CA
        assertDoesNotThrow(() -> signedCert.verify(caKeyPair.getPublic()),
                "CSR-signed cert should be verifiable with CA public key");

        // Verify the cert public key matches the CSR
        assertEquals(csrKeyPair.getPublic(), signedCert.getPublicKey(),
                "Signed cert public key should match CSR key pair");
    }

    @Test
    @DisplayName("Should generate client auth certificate with correct EKU")
    void shouldGenerateClientCertificateWithCorrectEku() throws Exception {
        KeyPair caKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.EC_P256);
        X500Name caSubject = builder.buildSubjectDn("EC Test CA", null, "TestOrg", null, null, "US");
        builder.generateRootCaCertificate(
                caSubject, caKeyPair, "SHA256withECDSA",
                BigInteger.ONE, LocalDateTime.now(), LocalDateTime.now().plusYears(10),
                -1, null);

        KeyPair clientKeyPair = keyPairGen.generateKeyPair(KeyAlgorithm.EC_P256);
        X500Name clientSubject = builder.buildSubjectDn("Client User", null, null, null, null, null);

        X509Certificate clientCert = builder.generateEndEntityCertificate(
                clientSubject, clientKeyPair.getPublic(), caSubject, caKeyPair,
                "SHA256withECDSA", BigInteger.valueOf(5),
                LocalDateTime.now(), LocalDateTime.now().plusDays(365),
                CertificateType.CLIENT,
                new String[]{"user@example.com"},
                null);

        assertNotNull(clientCert);
        assertTrue(clientCert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"),
                "Client cert should have clientAuth EKU");
    }
}