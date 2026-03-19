package com.certman.repository;

import com.certman.domain.Certificate;
import com.certman.domain.CertificateAuthority;
import com.certman.domain.CertificateStatus;
import com.certman.domain.CertificateType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, UUID> {

    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findByIssuingCa(CertificateAuthority ca);

    List<Certificate> findByStatus(CertificateStatus status);

    List<Certificate> findByCertificateType(CertificateType type);

    List<Certificate> findByCommonNameContainingIgnoreCase(String commonName);

    @Query("SELECT c FROM Certificate c WHERE c.status = 'ACTIVE' AND c.notAfter BETWEEN :now AND :threshold")
    List<Certificate> findExpiringCertificates(
            @Param("now") LocalDateTime now,
            @Param("threshold") LocalDateTime threshold);

    @Query("SELECT c FROM Certificate c WHERE c.status = 'REVOKED' AND c.issuingCa = :ca")
    List<Certificate> findRevokedByCA(@Param("ca") CertificateAuthority ca);

    @Query("SELECT c FROM Certificate c WHERE c.status = 'ACTIVE' AND c.notAfter < CURRENT_TIMESTAMP")
    List<Certificate> findExpiredButActive();

    @Query("SELECT COUNT(c) FROM Certificate c WHERE c.status = ?1")
    long countByStatus(CertificateStatus status);

    @Query("SELECT COUNT(c) FROM Certificate c WHERE c.certificateType = ?1")
    long countByType(CertificateType type);

    @Query("SELECT COUNT(c) FROM Certificate c WHERE c.issuingCa = ?1")
    long countByIssuingCa(CertificateAuthority ca);

    @Query("SELECT c FROM Certificate c WHERE c.status = 'ACTIVE' AND c.notAfter > CURRENT_TIMESTAMP ORDER BY c.notAfter ASC")
    List<Certificate> findActiveCertificatesOrderByExpiry();
}