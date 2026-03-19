# CertMan - Certificate Management Service

## Phase 1: Project Setup [x]
- [x] Create directory structure
- [x] Create pom.xml with Spring Boot 3.5.8, JDK 25, Bouncy Castle 1.79
- [x] Create application.yml, CertManApplication, configs

## Phase 2: Domain & Data Layer [x]
- [x] Create enums (KeyAlgorithm, CertificateStatus, CertificateType, etc.)
- [x] Create JPA entities (CertificateAuthority, Certificate, CertificateRequest, AuditLog)
- [x] Create Spring Data JPA repositories

## Phase 3: Certificate Engine [x]
- [x] KeyPairGenerator, CertificateBuilder, PemUtils
- [x] CrlGenerator, CertificateExporter

## Phase 4: Service Layer [x]
- [x] AuditService, CertificateAuthorityService
- [x] CertificateService, CrlService

## Phase 5: Controllers [x]
- [x] Dashboard, CA, Certificate, CSR, API controllers
- [x] GlobalExceptionHandler

## Phase 6: Frontend (Thymeleaf) [x]
- [x] Dark theme CSS, layout fragments
- [x] Dashboard, CA, Certificate, CSR templates

## Phase 7: Final Polish [x]
- [x] README.md documentation

## Phase 8: Surefire Test Suite [x]
- [x] Configure maven-surefire-plugin 3.5.2 in pom.xml
- [x] Create engine unit tests (KeyPairGeneratorTest, CertificateBuilderTest, PemUtilsTest, CertificateExporterTest)
- [x] Create service integration tests (CertificateAuthorityServiceTest, CertificateServiceTest)
- [x] Create full lifecycle test (CertificateLifecycleTest - 9 ordered steps)
- [x] Create application-test.yml for in-memory H2
- [x] Add @ActiveProfiles("test") to all @SpringBootTest classes
- [x] Fix Root CA serial number uniqueness (random 128-bit serial)
- [x] Fix EC key algorithm assertion (accept EC or ECDSA)
- [x] Run mvn clean test — ALL 52 TESTS PASSING ✅