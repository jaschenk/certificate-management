package com.certman.repository;

import com.certman.domain.CertificateRequest;
import com.certman.domain.RequestStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface CertificateRequestRepository extends JpaRepository<CertificateRequest, UUID> {

    List<CertificateRequest> findByRequestStatus(RequestStatus status);

    List<CertificateRequest> findByRequesterEmailIgnoreCase(String email);

    List<CertificateRequest> findByCommonNameContainingIgnoreCase(String commonName);

    @Query("SELECT COUNT(cr) FROM CertificateRequest cr WHERE cr.requestStatus = ?1")
    long countByStatus(RequestStatus status);

    @Query("SELECT cr FROM CertificateRequest cr ORDER BY cr.createdAt DESC")
    List<CertificateRequest> findAllOrderByCreatedAtDesc();

    List<CertificateRequest> findByRequestStatusOrderByCreatedAtDesc(RequestStatus status);
}