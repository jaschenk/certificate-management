package com.certman.service;

import com.certman.domain.*;
import com.certman.engine.CertificateBuilder;
import com.certman.engine.KeyPairGenerator;
import com.certman.engine.PemUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for CertificateService — validates the full certificate
 * lifecycle: issue, revoke, renew, CSR sign, and export.
 */
@SpringBootTest
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("CertificateService Integration Tests")
class CertificateServiceTest {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CertificateAuthorityService caService;

    @Autowired
    private KeyPairGenerator keyPairGenerator;

    @Autowired
    private CertificateBuilder certificateBuilder;

    @Autowired
    private PemUtils pemUtils;

    private CertificateAuthority testCa;

    @BeforeEach
    void setUp() {
        testCa = caService.createRootCa(
                "Test CA", "Test Root CA", "Test Organization",
                "PKI", "New York", "NY", "US",
                KeyAlgorithm.RSA_4096, 3650, -1);
    }

    @Test
    @DisplayName("Should issue a TLS server certificate")
    void shouldIssueTlsCertificate() {
        Certificate cert = certificateService.issueCertificate(
                testCa.getId(),
                "www.example.com",
                "Example Inc",
                "Engineering",
                "San Francisco", "CA", "US",
                "www.example.com,api.example.com",
                CertificateType.SERVER,
                KeyAlgorithm.RSA_2048,
                365);

        assertNotNull(cert.getId(), "Certificate ID should be assigned");
        assertEquals("www.example.com", cert.getCommonName());
        assertEquals(CertificateType.SERVER, cert.getCertificateType());
        assertEquals(CertificateStatus.ACTIVE, cert.getStatus());
        assertEquals(KeyAlgorithm.RSA_2048, cert.getKeyAlgorithm());
        assertNotNull(cert.getCertificatePem());
        assertNotNull(cert.getPrivateKeyPem());
        assertNotNull(cert.getSerialNumber());
        assertNotNull(cert.getThumbprintSha256());
        assertEquals(64, cert.getThumbprintSha256().length(),
                "SHA-256 thumbprint should be 64 hex chars");
        assertTrue(cert.isActive(), "Certificate should be active");
        assertEquals("www.example.com,api.example.com", cert.getSubjectAlternativeNames());
        assertEquals("digitalSignature, keyEncipherment", cert.getKeyUsage());
        assertEquals("serverAuth", cert.getExtendedKeyUsage());
    }

    @Test
    @DisplayName("Should issue client auth certificate")
    void shouldIssueClientCertificate() {
        Certificate cert = certificateService.issueCertificate(
                testCa.getId(),
                "John Doe",
                "Example Inc", null,
                null, null, "US",
                "john.doe@example.com",
                CertificateType.CLIENT,
                KeyAlgorithm.EC_P256,
                365);

        assertNotNull(cert.getId());
        assertEquals(CertificateType.CLIENT, cert.getCertificateType());
        assertEquals("clientAuth", cert.getExtendedKeyUsage());
    }

    @Test
    @DisplayName("Should revoke a certificate with reason")
    void shouldRevokeCertificate() {
        Certificate cert = certificateService.issueCertificate(
                testCa.getId(), "revoke-test.example.com",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER,
                KeyAlgorithm.RSA_2048, 365);

        Certificate revoked = certificateService.revokeCertificate(
                cert.getId(), RevocationReason.KEY_COMPROMISE);

        assertEquals(CertificateStatus.REVOKED, revoked.getStatus());
        assertEquals(RevocationReason.KEY_COMPROMISE, revoked.getRevocationReason());
        assertNotNull(revoked.getRevokedAt(), "Revocation timestamp should be set");
        assertTrue(revoked.isRevoked());
        assertFalse(revoked.isActive());
    }

    @Test
    @DisplayName("Should reject double revocation")
    void shouldRejectDoubleRevocation() {
        Certificate cert = certificateService.issueCertificate(
                testCa.getId(), "double-revoke.example.com",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER,
                KeyAlgorithm.RSA_2048, 365);

        certificateService.revokeCertificate(cert.getId(), RevocationReason.SUPERSEDED);

        assertThrows(IllegalStateException.class, () ->
                        certificateService.revokeCertificate(cert.getId(), RevocationReason.KEY_COMPROMISE),
                "Should not allow revoking an already revoked certificate");
    }

    @Test
    @DisplayName("Should renew a certificate (revoke old + issue new)")
    void shouldRenewCertificate() {
        Certificate original = certificateService.issueCertificate(
                testCa.getId(), "renew.example.com",
                "Org", null, null, null, "US",
                "renew.example.com",
                CertificateType.SERVER,
                KeyAlgorithm.RSA_2048, 365);

        Certificate renewed = certificateService.renewCertificate(original.getId(), 730);

        assertNotNull(renewed.getId());
        assertNotEquals(original.getId(), renewed.getId(),
                "Renewed cert should have a new ID");
        assertEquals("renew.example.com", renewed.getCommonName(),
                "Common name should be preserved");
        assertEquals(CertificateType.SERVER, renewed.getCertificateType(),
                "Type should be preserved");
        assertEquals(CertificateStatus.ACTIVE, renewed.getStatus(),
                "Renewed cert should be active");

        // Original should now be revoked
        Certificate oldCert = certificateService.getCertificateById(original.getId()).orElseThrow();
        assertEquals(CertificateStatus.REVOKED, oldCert.getStatus(),
                "Original cert should be revoked after renewal");
        assertEquals(RevocationReason.SUPERSEDED, oldCert.getRevocationReason());
    }

    @Test
    @DisplayName("Should submit, approve, and sign an external CSR")
    void shouldProcessExternalCsr() {
        // Generate an external CSR (simulating what a user would submit)
        KeyPair externalKeyPair = keyPairGenerator.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name csrSubject = certificateBuilder.buildSubjectDn(
                "external.example.com", null, "External Corp", null, null, "US");
        PKCS10CertificationRequest csr = certificateBuilder.generateCsr(
                csrSubject, externalKeyPair, "SHA256withRSA");
        String csrPem = pemUtils.toPem(csr);

        // Submit CSR
        CertificateRequest request = certificateService.submitCsr(
                csrPem,
                "external.example.com",
                "External Corp", null,
                null, null, "US",
                "external.example.com,www.external.example.com",
                CertificateType.SERVER,
                365,
                "Jane Doe",
                "jane@external.com",
                "Need TLS cert for production");

        assertNotNull(request.getId());
        assertEquals(RequestStatus.PENDING, request.getRequestStatus());
        assertEquals("external.example.com", request.getCommonName());

        // Verify pending count
        assertEquals(1, certificateService.countPendingRequests());

        // Approve and sign the CSR
        Certificate signedCert = certificateService.signCertificateRequest(
                request.getId(), testCa.getId(), 365);

        assertNotNull(signedCert.getId());
        assertEquals("external.example.com", signedCert.getCommonName());
        assertEquals(CertificateStatus.ACTIVE, signedCert.getStatus());
        assertNotNull(signedCert.getCertificatePem());
        assertTrue(signedCert.getCertificatePem().contains("BEGIN CERTIFICATE"));

        // CSR should be marked approved
        CertificateRequest updatedRequest = certificateService.getRequestById(request.getId()).orElseThrow();
        assertEquals(RequestStatus.APPROVED, updatedRequest.getRequestStatus());
        assertNotNull(updatedRequest.getProcessedAt());

        // No more pending
        assertEquals(0, certificateService.countPendingRequests());
    }

    @Test
    @DisplayName("Should reject a CSR with reason")
    void shouldRejectCsr() {
        KeyPair kp = keyPairGenerator.generateKeyPair(KeyAlgorithm.RSA_2048);
        X500Name subj = certificateBuilder.buildSubjectDn("rejected.example.com", null, "Org", null, null, "US");
        String csrPem = pemUtils.toPem(certificateBuilder.generateCsr(subj, kp, "SHA256withRSA"));

        CertificateRequest request = certificateService.submitCsr(
                csrPem, "rejected.example.com", "Org", null,
                null, null, "US", null,
                CertificateType.SERVER, 365, "Bob", "bob@org.com", null);

        CertificateRequest rejected = certificateService.rejectCertificateRequest(
                request.getId(), "Domain ownership not verified");

        assertEquals(RequestStatus.REJECTED, rejected.getRequestStatus());
        assertEquals("Domain ownership not verified", rejected.getRejectionReason());
        assertNotNull(rejected.getProcessedAt());
    }

    @Test
    @DisplayName("Should export certificate as PKCS#12")
    void shouldExportPkcs12() {
        Certificate cert = certificateService.issueCertificate(
                testCa.getId(), "export.example.com",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER,
                KeyAlgorithm.RSA_2048, 365);

        byte[] p12 = certificateService.exportAsPkcs12(cert.getId(), "exportPass123");

        assertNotNull(p12);
        assertTrue(p12.length > 0, "PKCS#12 should not be empty");
    }

    @Test
    @DisplayName("Should export certificate chain as PEM bundle")
    void shouldExportCertChainPem() {
        Certificate cert = certificateService.issueCertificate(
                testCa.getId(), "chain.example.com",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER,
                KeyAlgorithm.RSA_2048, 365);

        String chain = certificateService.exportCertificateChainPem(cert.getId());

        assertNotNull(chain);
        int certCount = chain.split("-----BEGIN CERTIFICATE-----").length - 1;
        assertEquals(2, certCount, "Chain should contain server cert + CA cert");
    }

    @Test
    @DisplayName("Should export certificate as DER")
    void shouldExportDer() {
        Certificate cert = certificateService.issueCertificate(
                testCa.getId(), "der.example.com",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER,
                KeyAlgorithm.RSA_2048, 365);

        byte[] der = certificateService.exportCertificateDer(cert.getId());

        assertNotNull(der);
        assertTrue(der.length > 0);
    }

    @Test
    @DisplayName("Should search certificates by common name")
    void shouldSearchByCommonName() {
        certificateService.issueCertificate(testCa.getId(), "alpha.example.com",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER, KeyAlgorithm.RSA_2048, 365);
        certificateService.issueCertificate(testCa.getId(), "beta.example.com",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER, KeyAlgorithm.RSA_2048, 365);
        certificateService.issueCertificate(testCa.getId(), "gamma.test.io",
                "Org", null, null, null, "US",
                null, CertificateType.SERVER, KeyAlgorithm.RSA_2048, 365);

        List<Certificate> results = certificateService.searchByCommonName("example");
        assertEquals(2, results.size(), "Should find 2 certs matching 'example'");

        List<Certificate> all = certificateService.getAllCertificates();
        assertEquals(3, all.size(), "Should have 3 total certificates");
    }
}