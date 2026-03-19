package com.certman.service;

import com.certman.domain.AuditLog;
import com.certman.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service for recording and querying audit trail entries.
 */
@Service
@Transactional
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void logAction(String action, String entityType, String entityId, String details) {
        AuditLog entry = AuditLog.create(action, entityType, entityId, details);
        auditLogRepository.save(entry);
        log.info("AUDIT: {} {} [{}] - {}", action, entityType, entityId, details);
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getRecentActivity() {
        return auditLogRepository.findRecentActivity();
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getAuditTrailForEntity(String entityType, String entityId) {
        return auditLogRepository.findByEntityTypeAndEntityId(entityType, entityId);
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAllOrderByTimestampDesc();
    }
}