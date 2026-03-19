package com.certman.repository;

import com.certman.domain.CertificateAuthority;
import com.certman.domain.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateAuthorityRepository extends JpaRepository<CertificateAuthority, UUID> {

    Optional<CertificateAuthority> findByName(String name);

    List<CertificateAuthority> findByStatus(CertificateStatus status);

    @Query("SELECT ca FROM CertificateAuthority ca WHERE ca.parentCa IS NULL")
    List<CertificateAuthority> findRootCas();

    @Query("SELECT ca FROM CertificateAuthority ca WHERE ca.parentCa IS NOT NULL")
    List<CertificateAuthority> findIntermediateCas();

    List<CertificateAuthority> findByNotAfterBefore(LocalDateTime date);

    @Query("SELECT ca FROM CertificateAuthority ca WHERE ca.status = 'ACTIVE' AND ca.notAfter > CURRENT_TIMESTAMP")
    List<CertificateAuthority> findActiveCas();

    boolean existsByName(String name);

    @Query("SELECT COUNT(ca) FROM CertificateAuthority ca WHERE ca.status = ?1")
    long countByStatus(CertificateStatus status);
}