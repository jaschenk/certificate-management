# CertMan — Certificate Management Service

A full-featured, enterprise-grade PKI Certificate Management Service built with **Java JDK 25** and **Spring Boot 4.1.2**. Provides a modern dark-themed web UI (Thymeleaf) for managing Certificate Authorities, X.509 certificates, and Certificate Signing Requests.

---

## Features

### PKI Standards Compliance
- **RFC 5280** — X.509 PKI Certificate and CRL Profile
- **RFC 2986** — PKCS#10 Certificate Signing Request Syntax
- **RFC 7292** — PKCS#12 Personal Information Exchange Syntax
- **RFC 7468** — PEM Encoding
- **NIST SP 800-57** — Key length and algorithm recommendations

### Certificate Authority Management
- Create **Root CAs** (self-signed) and **Intermediate CAs** (signed by parent)
- Support for RSA (2048/4096) and ECDSA (P-256/P-384/P-521) key algorithms
- Path length constraints for CA hierarchy control
- CA certificate download in PEM format

### Certificate Lifecycle Management
- **Issue** end-entity certificates (Server/TLS, Client, Code Signing, Email/S-MIME)
- **Revoke** certificates with RFC 5280 reason codes
- **Renew** certificates with automatic revocation of predecessor
- Subject Alternative Names (DNS, IP, Email)
- Key Usage and Extended Key Usage extensions
- SHA-256 thumbprint calculation

### Certificate Export Formats
- **PEM** — Base64 encoded certificate
- **DER** — Binary ASN.1 encoding
- **PKCS#12 / PFX** — Password-protected bundle with private key and chain
- **Certificate Chain** — Full PEM bundle (cert + CA)
- **Private Key** — PKCS#8 PEM format

### CSR Workflow
- Submit external PKCS#10 CSRs for review
- Approve & sign CSRs with any active CA
- Reject CSRs with reason
- Track request status (Pending → Approved/Rejected)

### Certificate Revocation Lists (CRL)
- Automatic CRL generation per CA
- CRL Distribution Point embedded in certificates
- DER-encoded CRL download via REST API
- CRL caching with configurable expiry

### Dashboard & Monitoring
- Real-time statistics (active, expired, revoked, pending)
- Certificates expiring within 30 days
- Recent audit activity log
- Quick action shortcuts

### Audit Trail
- All operations logged with timestamp
- Entity-level audit history
- Recent activity feed on dashboard

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Runtime** | Java JDK 25 (OpenJDK 25.0.2) |
| **Framework** | Spring Boot 4.1.2 (Spring Framework 7.0) |
| **Frontend** | Thymeleaf + Custom CSS (Dark Theme) |
| **Cryptography** | Bouncy Castle 1.79 (bcprov + bcpkix) |
| **Database** | H2 (embedded, file-based) — swap to PostgreSQL for production |
| **ORM** | Spring Data JPA / Hibernate 7.4 |
| **Build** | Maven 3.9.9 |

---

## Quick Start

### Prerequisites
- Java JDK 25+ ([download](https://jdk.java.net/25/))
- Maven 3.9+ ([download](https://maven.apache.org/download.cgi))

### Build & Run

```bash
# Clone and build
cd certman
mvn clean package -DskipTests

# Run
java --enable-preview -jar target/certman-1.0.0-SNAPSHOT.jar
```

The application starts on **http://localhost:8443/certman**

### Run the Tests

```bash
mvn clean test                                   # 57 tests
mvn clean test -Dsurefire.runOrder=alphabetical  # same suite, fixed class order
```

Certificate and CA serial numbers are random 127-bit values (RFC 5280 §4.1.2.2), unique across all CAs.

### Default Endpoints

| URL | Description |
|-----|-------------|
| `/certman/dashboard` | Main dashboard |
| `/certman/ca` | Certificate Authorities |
| `/certman/certificates` | Certificates |
| `/certman/csr` | CSR Requests |
| `/certman/api/v1/health` | Health check API |
| `/certman/h2-console` | Database console |

---

## Project Structure

```
certman/
├── src/main/java/com/certman/
│   ├── CertManApplication.java          # Main entry point
│   ├── config/
│   │   ├── CertManProperties.java       # Typed config properties
│   │   └── WebConfig.java               # MVC configuration
│   ├── controller/
│   │   ├── DashboardController.java     # Dashboard page
│   │   ├── CertificateAuthorityController.java
│   │   ├── CertificateController.java   # Cert CRUD + downloads
│   │   ├── CsrController.java          # CSR workflow
│   │   ├── ApiController.java           # REST API (CRL, health)
│   │   └── GlobalExceptionHandler.java  # Error handling
│   ├── domain/                          # JPA entities & enums
│   │   ├── CertificateAuthority.java
│   │   ├── Certificate.java
│   │   ├── CertificateRequest.java
│   │   ├── AuditLog.java
│   │   ├── KeyAlgorithm.java
│   │   ├── CertificateType.java
│   │   ├── CertificateStatus.java
│   │   ├── RevocationReason.java
│   │   └── RequestStatus.java
│   ├── dto/
│   │   └── DashboardStats.java
│   ├── engine/                          # Core PKI cryptography
│   │   ├── KeyPairGenerator.java
│   │   ├── SerialNumberGenerator.java   # Random certificate serial numbers
│   │   ├── CertificateBuilder.java      # X.509v3 cert generation
│   │   ├── CertificateExporter.java     # PEM/DER/PKCS#12 export
│   │   ├── CrlGenerator.java           # CRL v2 generation
│   │   ├── PemUtils.java               # PEM encode/decode
│   │   └── CertificateEngineException.java
│   ├── repository/                      # Spring Data JPA repos
│   │   ├── CertificateAuthorityRepository.java
│   │   ├── CertificateRepository.java
│   │   ├── CertificateRequestRepository.java
│   │   └── AuditLogRepository.java
│   └── service/                         # Business logic
│       ├── CertificateAuthorityService.java
│       ├── CertificateService.java
│       ├── CrlService.java
│       └── AuditService.java
├── src/main/resources/
│   ├── application.yml                  # App configuration
│   ├── static/css/style.css            # Dark theme CSS
│   └── templates/                       # Thymeleaf templates
│       ├── fragments/layout.html
│       ├── dashboard/index.html
│       ├── ca/{list,create,detail}.html
│       ├── certificate/{list,create,detail}.html
│       └── csr/{list,submit,detail}.html
└── pom.xml
```

---

## Configuration

Key settings in `application.yml`:

```yaml
certman:
  defaults:
    key-algorithm: RSA          # Default key algorithm
    key-size: 4096              # Default key size
    signature-algorithm: SHA384withRSA
    validity-days: 365          # Default cert validity
    ca-validity-days: 3650      # Default CA validity (10 years)
  keystore:
    base-path: ./data/keystores
  crl:
    distribution-point: http://localhost:8443/certman/api/v1/crl
    update-interval-hours: 24
```

### Database

By default uses embedded **H2** with file persistence (`./data/certmandb`). For production, switch to PostgreSQL:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/certman
    driver-class-name: org.postgresql.Driver
    username: certman
    password: ${DB_PASSWORD}
  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
```

---

## Supported Key Algorithms

| Algorithm | Key Size | Signature | Security Level |
|-----------|----------|-----------|---------------|
| RSA 2048 | 2048-bit | SHA256withRSA | 112-bit |
| RSA 4096 | 4096-bit | SHA384withRSA | ~140-bit |
| ECDSA P-256 | 256-bit | SHA256withECDSA | 128-bit |
| ECDSA P-384 | 384-bit | SHA384withECDSA | 192-bit |
| ECDSA P-521 | 521-bit | SHA512withECDSA | 256-bit |

---

## License

This project is provided as-is for educational and internal enterprise use.