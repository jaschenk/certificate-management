package com.certman;

import com.certman.domain.*;
import com.certman.engine.CertificateBuilder;
import com.certman.engine.KeyPairGenerator;
import com.certman.engine.PemUtils;
import com.certman.service.AuditService;
import com.certman.service.CertificateAuthorityService;
import com.certman.service.CertificateService;
import com.certman.service.CrlService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full Certificate Lifecycle Integration Test Suite
 * 
 * Exercises the complete PKI workflow:
 * 
 * 1. Create Root CA
 * 2. Create Intermediate CA (signed by Root)
 * 3. Request a TLS server certificate (generate CSR → submit → approve)
 * 4. Issue the certificate and verify its properties
 * 5. Export certificate in multiple formats (PEM, DER, PKCS#12, chain)
 * 6. Verify certificate chain trust (server → intermediate → root)
 * 7. Revoke the certificate
 * 8. Generate CRL and verify revoked cert appears
 * 9. Renew a certificate
 * 10. Verify audit trail captured all operations
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("Full Certificate Lifecycle Test Suite")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CertificateLifecycleTest {

    @Autowired private CertificateAuthorityService caService;
    @Autowired private CertificateService certificateService;
    @Autowired private CrlService crlService;
    @Autowired private AuditService auditService;
    @Autowired private KeyPairGenerator keyPairGenerator;
    @Autowired private CertificateBuilder certificateBuilder;
    @Autowired private PemUtils pemUtils;

    // Shared state across ordered tests
    private CertificateAuthority rootCa;
    private CertificateAuthority intermediateCa;
    private Certificate serverCert;
    private Certificate csrSignedCert;

    // ========================================================
    // Step 1: Create Root CA
    // ========================================================

    @Test
    @Order(1)
    @DisplayName("Step 1: Create Root CA with RSA-4096")
    void step1_createRootCa() {
        rootCa = caService.createRootCa(
                "Lifecycle Root CA",
                "Lifecycle Test Root CA",
                "Lifecycle Test Organization",
                "PKI Operations",
                "New York",
                "NY",
                "US",
                KeyAlgorithm.RSA_4096,
                3650,
                -1);

        assertNotNull(rootCa.getId(), "Root CA should be persisted with ID");
        assertTrue(rootCa.isRootCa(), "Should be a Root CA (no parent)");
        assertEquals(CertificateStatus.ACTIVE, rootCa.getStatus());
        assertTrue(rootCa.getCertificatePem().contains("BEGIN CERTIFICATE"));

        // Verify the CA certificate is valid X.509
        X509Certificate x509 = pemUtils.parseCertificate(rootCa.getCertificatePem());
        assertEquals(x509.getSubjectX500Principal(), x509.getIssuerX500Principal(),
                "Root CA should be self-signed");
        assertTrue(x509.getBasicConstraints() >= 0, "Should have CA=true");

        System.out.println("✅ Root CA created: " + rootCa.getName() + " [" + rootCa.getId() + "]");
    }

    // ========================================================
    // Step 2: Create Intermediate CA
    // ========================================================

    @Test
    @Order(2)
    @DisplayName("Step 2: Create Intermediate CA signed by Root")
    void step2_createIntermediateCa() {
        intermediateCa = caService.createIntermediateCa(
                "Lifecycle Intermediate CA",
                "Lifecycle Test Intermediate CA",
                "Lifecycle Test Organization",
                "TLS Issuing",
                "New York",
                "NY",
                "US",
                KeyAlgorithm.RSA_4096,
                1825,
                0,     // pathLength=0 → can only issue end-entity certs
                rootCa.getId());

        assertNotNull(intermediateCa.getId());
        assertFalse(intermediateCa.isRootCa(), "Should be an Intermediate CA");
        assertEquals(rootCa.getId(), intermediateCa.getParentCa().getId());

        // Verify chain: intermediate cert signed by root
        X509Certificate intCert = pemUtils.parseCertificate(intermediateCa.getCertificatePem());
        X509Certificate rootCert = pemUtils.parseCertificate(rootCa.getCertificatePem());
        assertDoesNotThrow(() -> intCert.verify(rootCert.getPublicKey()),
                "Intermediate CA cert should be verifiable with Root CA public key");

        System.out.println("✅ Intermediate CA created: " + intermediateCa.getName());
    }

    // ========================================================
    // Step 3: Issue TLS Server Certificate directly
    // ========================================================

    @Test
    @Order(3)
    @DisplayName("Step 3: Issue TLS server certificate from Intermediate CA")
    void step3_issueServerCertificate() {
        serverCert = certificateService.issueCertificate(
                intermediateCa.getId(),
                "lifecycle.example.com",
                "Example Corporation",
                "Engineering",
                "San Francisco",
                "CA",
                "US",
                "lifecycle.example.com,www.lifecycle.example.com,192.168.1.100",
                CertificateType.SERVER,
                KeyAlgorithm.RSA_2048,
                365);

        assertNotNull(serverCert.getId());
        assertEquals("lifecycle.example.com", serverCert.getCommonName());
        assertEquals(CertificateType.SERVER, serverCert.getCertificateType());
        assertEquals(CertificateStatus.ACTIVE, serverCert.getStatus());
        assertTrue(serverCert.isActive());
        assertTrue(serverCert.getDaysUntilExpiry() > 360);
        assertEquals("serverAuth", serverCert.getExtendedKeyUsage());

        // Verify the issued certificate chain: server → intermediate → root
        X509Certificate x509Server = pemUtils.parseCertificate(serverCert.getCertificatePem());
        X509Certificate x509Int = pemUtils.parseCertificate(intermediateCa.getCertificatePem());
        X509Certificate x509Root = pemUtils.parseCertificate(rootCa.getCertificatePem());

        assertDoesNotThrow(() -> x509Server.verify(x509Int.getPublicKey()),
                "Server cert should be signed by Intermediate CA");
        assertDoesNotThrow(() -> x509Int.verify(x509Root.getPublicKey()),
                "Intermediate CA should be signed by Root CA");

        // Not a CA
        assertEquals(-1, x509Server.getBasicConstraints(), "Server cert should not be a CA");

        System.out.println("✅ Server certificate issued: " + serverCert.getCommonName() +
                " [Serial: " + serverCert.getSerialNumber() + "]");
    }

    // ========================================================
    // Step 4: Submit external CSR → Approve → Get certificate
    // ========================================================

    @Test
    @Order(4)
    @DisplayName("Step 4: Submit CSR, approve it, and receive signed certificate")
    void step4_submitAndApproveCsr() {
        // Simulate external CSR generation (what a user would do with openssl)
        java.security.KeyPair externalKeyPair = keyPairGenerator.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name csrSubject = certificateBuilder.buildSubjectDn(
                "csr.lifecycle.example.com", null, "CSR Test Corp", null, null, "US");
        PKCS10CertificationRequest csr = certificateBuilder.generateCsr(
                csrSubject, externalKeyPair, "SHA256withRSA");
        String csrPem = pemUtils.toPem(csr);

        // Submit CSR
        CertificateRequest request = certificateService.submitCsr(
                csrPem,
                "csr.lifecycle.example.com",
                "CSR Test Corp",
                "Web Team",
                "Austin", "TX", "US",
                "csr.lifecycle.example.com,csr2.lifecycle.example.com",
                CertificateType.SERVER,
                365,
                "Alice Engineer",
                "alice@csrtest.com",
                "Production web server certificate");

        assertNotNull(request.getId());
        assertEquals(RequestStatus.PENDING, request.getRequestStatus());
        assertEquals(1, certificateService.countPendingRequests());

        System.out.println("✅ CSR submitted: " + request.getId());

        // Approve and sign
        csrSignedCert = certificateService.signCertificateRequest(
                request.getId(), intermediateCa.getId(), 365);

        assertNotNull(csrSignedCert.getId());
        assertEquals("csr.lifecycle.example.com", csrSignedCert.getCommonName());
        assertEquals(CertificateStatus.ACTIVE, csrSignedCert.getStatus());
        assertTrue(csrSignedCert.getCertificatePem().contains("BEGIN CERTIFICATE"));

        // Verify the signed certificate
        X509Certificate x509Signed = pemUtils.parseCertificate(csrSignedCert.getCertificatePem());
        X509Certificate x509Int = pemUtils.parseCertificate(intermediateCa.getCertificatePem());
        assertDoesNotThrow(() -> x509Signed.verify(x509Int.getPublicKey()),
                "CSR-signed cert should be verifiable with Intermediate CA key");

        // Public key in cert should match external CSR key pair
        assertEquals(externalKeyPair.getPublic(), x509Signed.getPublicKey(),
                "Signed cert public key should match the CSR's key pair");

        // Request should now be approved
        CertificateRequest updatedReq = certificateService.getRequestById(request.getId()).orElseThrow();
        assertEquals(RequestStatus.APPROVED, updatedReq.getRequestStatus());
        assertEquals(0, certificateService.countPendingRequests());

        System.out.println("✅ CSR approved and certificate issued: " + csrSignedCert.getId());
    }

    // ========================================================
    // Step 5: Export certificate in all formats
    // ========================================================

    @Test
    @Order(5)
    @DisplayName("Step 5: Export server certificate in PEM, DER, PKCS#12, and chain formats")
    void step5_exportCertificateFormats() throws Exception {
        // PEM
        String pem = serverCert.getCertificatePem();
        assertNotNull(pem);
        assertTrue(pem.contains("BEGIN CERTIFICATE"));

        // DER
        byte[] der = certificateService.exportCertificateDer(serverCert.getId());
        assertNotNull(der);
        assertTrue(der.length > 0);

        // Certificate chain PEM
        String chain = certificateService.exportCertificateChainPem(serverCert.getId());
        assertNotNull(chain);
        int certCount = chain.split("-----BEGIN CERTIFICATE-----").length - 1;
        assertEquals(2, certCount, "Chain should have server cert + CA cert");

        // PKCS#12
        String password = "lifecycle-test-2025";
        byte[] p12 = certificateService.exportAsPkcs12(serverCert.getId(), password);
        assertNotNull(p12);
        assertTrue(p12.length > 100, "PKCS#12 should have substantial content");

        // Verify PKCS#12 can be loaded back
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12), password.toCharArray());
        assertTrue(ks.containsAlias("lifecycle.example.com"));

        java.security.Key loadedKey = ks.getKey("lifecycle.example.com", password.toCharArray());
        assertNotNull(loadedKey, "Should retrieve private key from PKCS#12");

        X509Certificate loadedCert = (X509Certificate) ks.getCertificate("lifecycle.example.com");
        assertEquals(serverCert.getCommonName(),
                loadedCert.getSubjectX500Principal().getName().split("CN=")[1].split(",")[0],
                "Loaded cert CN should match");

        java.security.cert.Certificate[] loadedChain = ks.getCertificateChain("lifecycle.example.com");
        assertEquals(2, loadedChain.length, "PKCS#12 chain should have 2 certs");

        System.out.println("✅ All export formats verified: PEM, DER, PKCS#12 (with chain), Chain PEM");
    }

    // ========================================================
    // Step 6: Revoke certificate and generate CRL
    // ========================================================

    @Test
    @Order(6)
    @DisplayName("Step 6: Revoke certificate and verify CRL contains it")
    void step6_revokeAndCheckCrl() {
        // Revoke the server certificate
        Certificate revoked = certificateService.revokeCertificate(
                serverCert.getId(), RevocationReason.KEY_COMPROMISE);

        assertEquals(CertificateStatus.REVOKED, revoked.getStatus());
        assertEquals(RevocationReason.KEY_COMPROMISE, revoked.getRevocationReason());
        assertNotNull(revoked.getRevokedAt());
        assertFalse(revoked.isActive());

        // Generate CRL for the intermediate CA
        X509CRL crl = crlService.generateCrl(intermediateCa);
        assertNotNull(crl, "CRL should not be null");

        // CRL should contain the revoked certificate
        assertNotNull(crl.getRevokedCertificate(
                        new java.math.BigInteger(serverCert.getSerialNumber(), 16)),
                "CRL should contain the revoked server certificate");

        // CRL DER export
        byte[] crlDer = crlService.getCrlDer(intermediateCa);
        assertNotNull(crlDer);
        assertTrue(crlDer.length > 0);

        System.out.println("✅ Certificate revoked and CRL generated with " +
                crl.getRevokedCertificates().size() + " entry/entries");
    }

    // ========================================================
    // Step 7: Renew the CSR-signed certificate
    // ========================================================

    @Test
    @Order(7)
    @DisplayName("Step 7: Renew a certificate (revoke old + issue new)")
    void step7_renewCertificate() {
        Certificate renewed = certificateService.renewCertificate(csrSignedCert.getId(), 730);

        assertNotNull(renewed.getId());
        assertNotEquals(csrSignedCert.getId(), renewed.getId(),
                "Renewed cert should have a new ID");
        assertEquals("csr.lifecycle.example.com", renewed.getCommonName(),
                "CN should be preserved");
        assertEquals(CertificateStatus.ACTIVE, renewed.getStatus());

        // Original should be revoked as superseded
        Certificate old = certificateService.getCertificateById(csrSignedCert.getId()).orElseThrow();
        assertEquals(CertificateStatus.REVOKED, old.getStatus());
        assertEquals(RevocationReason.SUPERSEDED, old.getRevocationReason());

        System.out.println("✅ Certificate renewed: " + renewed.getId() +
                " (old " + csrSignedCert.getId() + " revoked as SUPERSEDED)");
    }

    // ========================================================
    // Step 8: Verify audit trail
    // ========================================================

    @Test
    @Order(8)
    @DisplayName("Step 8: Verify complete audit trail for all operations")
    void step8_verifyAuditTrail() {
        var auditLogs = auditService.getAllAuditLogs();

        assertFalse(auditLogs.isEmpty(), "Audit log should not be empty");

        // Check that key operations were logged
        var actions = auditLogs.stream().map(AuditLog::getAction).toList();
        assertTrue(actions.contains("CREATE_ROOT_CA"), "Should log Root CA creation");
        assertTrue(actions.contains("CREATE_INTERMEDIATE_CA"), "Should log Intermediate CA creation");
        assertTrue(actions.contains("ISSUE_CERTIFICATE"), "Should log certificate issuance");
        assertTrue(actions.contains("SUBMIT_CSR"), "Should log CSR submission");
        assertTrue(actions.contains("SIGN_CSR"), "Should log CSR signing");
        assertTrue(actions.contains("REVOKE_CERTIFICATE"), "Should log revocation");
        assertTrue(actions.contains("RENEW_CERTIFICATE"), "Should log renewal");

        System.out.println("✅ Audit trail verified: " + auditLogs.size() + " entries logged");
        System.out.println("\n=== AUDIT TRAIL ===");
        auditLogs.forEach(log ->
                System.out.println("  " + log.getTimestamp() + " | " +
                        log.getAction() + " | " + log.getDetails()));
    }

    // ========================================================
    // Step 9: Verify final statistics
    // ========================================================

    @Test
    @Order(9)
    @DisplayName("Step 9: Verify final certificate inventory statistics")
    void step9_verifyStatistics() {
        long totalCas = caService.getAllCas().size();
        long activeCerts = certificateService.countByStatus(CertificateStatus.ACTIVE);
        long revokedCerts = certificateService.countByStatus(CertificateStatus.REVOKED);
        long totalCerts = certificateService.getAllCertificates().size();

        assertEquals(2, totalCas, "Should have 2 CAs (root + intermediate)");
        assertTrue(activeCerts >= 1, "Should have at least 1 active cert (the renewed one)");
        assertTrue(revokedCerts >= 2, "Should have at least 2 revoked certs (original server + CSR-signed)");
        assertTrue(totalCerts >= 3, "Should have at least 3 total certs");

        System.out.println("\n=== FINAL STATISTICS ===");
        System.out.println("  CAs:              " + totalCas);
        System.out.println("  Active certs:     " + activeCerts);
        System.out.println("  Revoked certs:    " + revokedCerts);
        System.out.println("  Total certs:      " + totalCerts);
        System.out.println("\n✅ Full certificate lifecycle test completed successfully!");
    }
}