package com.certman.service;

import com.certman.domain.CertificateAuthority;
import com.certman.domain.CertificateStatus;
import com.certman.domain.KeyAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for CertificateAuthorityService.
 * Uses in-memory H2 database with Spring Boot test context.
 */
@SpringBootTest
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("CertificateAuthorityService Integration Tests")
class CertificateAuthorityServiceTest {

    @Autowired
    private CertificateAuthorityService caService;

    @Test
    @DisplayName("Should create a Root CA with RSA 4096")
    void shouldCreateRootCa() {
        CertificateAuthority ca = caService.createRootCa(
                "Test Root CA",
                "Test Root CA",
                "Test Organization",
                "IT Security",
                "New York",
                "NY",
                "US",
                KeyAlgorithm.RSA_4096,
                3650,
                -1);

        assertNotNull(ca.getId(), "CA ID should be assigned");
        assertEquals("Test Root CA", ca.getName());
        assertEquals("Test Root CA", ca.getCommonName());
        assertEquals(KeyAlgorithm.RSA_4096, ca.getKeyAlgorithm());
        assertEquals(CertificateStatus.ACTIVE, ca.getStatus());
        assertTrue(ca.isRootCa(), "Should be a Root CA");
        assertNotNull(ca.getCertificatePem(), "Certificate PEM should not be null");
        assertNotNull(ca.getPrivateKeyPem(), "Private key PEM should not be null");
        assertTrue(ca.getCertificatePem().contains("BEGIN CERTIFICATE"));
        assertTrue(ca.getPrivateKeyPem().contains("PRIVATE KEY"));
    }

    @Test
    @DisplayName("Should create Root CA with EC P-384 algorithm")
    void shouldCreateRootCaWithEc() {
        CertificateAuthority ca = caService.createRootCa(
                "EC Root CA", "EC Root CA", "TestOrg", null,
                null, null, "US",
                KeyAlgorithm.EC_P384, 3650, -1);

        assertNotNull(ca.getId());
        assertEquals(KeyAlgorithm.EC_P384, ca.getKeyAlgorithm());
        assertEquals("SHA384withECDSA", ca.getSignatureAlgorithm());
    }

    @Test
    @DisplayName("Should reject duplicate CA names")
    void shouldRejectDuplicateCaName() {
        caService.createRootCa("Unique CA", "CN", "O", null, null, null, "US",
                KeyAlgorithm.RSA_2048, 365, -1);

        assertThrows(IllegalArgumentException.class, () ->
                caService.createRootCa("Unique CA", "CN2", "O2", null, null, null, "US",
                        KeyAlgorithm.RSA_2048, 365, -1),
                "Should reject duplicate CA name");
    }

    @Test
    @DisplayName("Should create Intermediate CA signed by Root CA")
    void shouldCreateIntermediateCa() {
        CertificateAuthority rootCa = caService.createRootCa(
                "Parent Root", "Parent Root CA", "TestOrg", null,
                null, null, "US",
                KeyAlgorithm.RSA_4096, 3650, -1);

        CertificateAuthority intCa = caService.createIntermediateCa(
                "Sub CA", "Intermediate CA", "TestOrg", "Dept",
                null, null, "US",
                KeyAlgorithm.RSA_4096, 1825, 0,
                rootCa.getId());

        assertNotNull(intCa.getId());
        assertFalse(intCa.isRootCa(), "Should not be a Root CA");
        assertNotNull(intCa.getParentCa(), "Should have parent CA");
        assertEquals(rootCa.getId(), intCa.getParentCa().getId());
        assertEquals(CertificateStatus.ACTIVE, intCa.getStatus());
    }

    @Test
    @DisplayName("Should list all CAs and filter by status")
    void shouldListAndFilterCas() {
        caService.createRootCa("CA-1", "CA One", "Org", null, null, null, "US",
                KeyAlgorithm.RSA_2048, 3650, -1);
        caService.createRootCa("CA-2", "CA Two", "Org", null, null, null, "US",
                KeyAlgorithm.EC_P256, 3650, -1);

        List<CertificateAuthority> all = caService.getAllCas();
        assertEquals(2, all.size(), "Should have 2 CAs");

        List<CertificateAuthority> active = caService.getActiveCas();
        assertEquals(2, active.size(), "Both should be active");

        long count = caService.countByStatus(CertificateStatus.ACTIVE);
        assertEquals(2, count);
    }
}