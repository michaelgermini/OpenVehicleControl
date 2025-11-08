# 🔒 Chapter 7: Security and Compliance

## 7.1 Software Security (OWASP, CVE Scanning)

### The Cybersecurity Imperative in Connected Vehicles

Vehicle control systems represent a convergence of critical infrastructure security challenges with automotive safety requirements. A single vulnerability could impact passenger safety, operational efficiency, and public trust. Understanding cybersecurity in this context requires recognizing that vehicles are now rolling computers with 100+ million lines of code and dozens of networked systems.

#### OWASP Principles for Vehicle Control Systems

##### **The OWASP Methodology Applied to Vehicles**
While OWASP (Open Web Application Security Project) originated in web security, its principles provide essential guidance for vehicle control systems:

**Threat Modeling:**
- **STRIDE Framework**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- **Attack Trees**: Hierarchical representation of attack paths
- **Risk Assessment**: Likelihood × Impact calculations

**Secure Development Lifecycle:**
```python
# Example: Secure coding practices in vehicle control
class SecureCommandValidator:
    def __init__(self, crypto_verifier, rate_limiter, audit_logger):
        self.crypto = crypto_verifier
        self.rate_limiter = rate_limiter
        self.audit = audit_logger

    async def validate_command(self, command: dict, context: dict) -> ValidationResult:
        """Multi-layered command validation"""

        # 1. Rate limiting check
        if not await self.rate_limiter.check_limit(context['client_id']):
            await self.audit.log_security_event('RATE_LIMIT_EXCEEDED', context)
            return ValidationResult.REJECTED

        # 2. Authentication verification
        if not await self._verify_authentication(command):
            await self.audit.log_security_event('AUTHENTICATION_FAILED', context)
            return ValidationResult.REJECTED

        # 3. Authorization check
        if not await self._check_authorization(command, context):
            await self.audit.log_security_event('AUTHORIZATION_FAILED', context)
            return ValidationResult.REJECTED

        # 4. Input validation and sanitization
        sanitized_command = await self._sanitize_input(command)
        if not sanitized_command:
            await self.audit.log_security_event('INPUT_VALIDATION_FAILED', context)
            return ValidationResult.REJECTED

        # 5. Business rule validation
        if not await self._validate_business_rules(sanitized_command):
            await self.audit.log_security_event('BUSINESS_RULE_VIOLATION', context)
            return ValidationResult.REJECTED

        return ValidationResult.ACCEPTED
```

#### Common Vulnerabilities in Vehicle Control Systems

##### **Injection Attacks**
Command injection through protocol interfaces:

**CAN Bus Injection:**
```python
# Vulnerable: Direct command execution without validation
async def execute_can_command(self, raw_command: bytes):
    # DANGER: No validation or sanitization
    await self.can_interface.send(raw_command)

# Secure: Validated command execution
async def execute_can_command_secure(self, command: dict):
    # Validate command structure
    validated_command = CANCommandSchema.validate(command)

    # Check command whitelist
    if validated_command['arbitration_id'] not in ALLOWED_CAN_IDS:
        raise SecurityException("Unauthorized CAN ID")

    # Encode securely
    encoded_command = await self._encode_can_command(validated_command)

    # Log for audit
    await self.audit_logger.log_command_execution(validated_command)

    await self.can_interface.send(encoded_command)
```

**MQTT Topic Injection:**
```python
# Vulnerable: Dynamic topic subscription
async def subscribe_to_topic(self, topic: str):
    # DANGER: Allows subscription to any topic
    await self.mqtt_client.subscribe(topic)

# Secure: Topic validation and authorization
async def subscribe_to_topic_secure(self, topic: str, client_permissions: dict):
    # Validate topic format
    if not self._is_valid_topic_format(topic):
        raise SecurityException("Invalid topic format")

    # Check topic authorization
    if not self._client_can_access_topic(topic, client_permissions):
        raise SecurityException("Topic access denied")

    # Rate limit subscriptions
    if not await self.rate_limiter.check_subscription_limit():
        raise SecurityException("Subscription rate limit exceeded")

    await self.mqtt_client.subscribe(topic)
```

##### **Authentication Bypass**
Weak authentication mechanisms:

**Token-Based Authentication:**
```python
# Secure JWT validation with multiple checks
class JWTAuthenticator:
    def __init__(self, key_manager, audit_logger):
        self.keys = key_manager
        self.audit = audit_logger

    async def authenticate_request(self, token: str, request_context: dict) -> AuthResult:
        try:
            # Decode without verification first for logging
            unverified_header = jwt.get_unverified_header(token)

            # Verify algorithm is expected
            if unverified_header['alg'] not in ALLOWED_ALGORITHMS:
                await self.audit.log_security_event('INVALID_ALGORITHM', {
                    'algorithm': unverified_header.get('alg'),
                    'context': request_context
                })
                return AuthResult.FAILED

            # Verify signature with appropriate key
            decoded = jwt.decode(
                token,
                self.keys.get_public_key(),
                algorithms=ALLOWED_ALGORITHMS,
                audience=EXPECTED_AUDIENCE,
                issuer=EXPECTED_ISSUER,
                options={
                    'require_exp': True,
                    'require_iat': True,
                    'require_nbf': True
                }
            )

            # Check token revocation
            if await self._is_token_revoked(decoded['jti']):
                return AuthResult.FAILED

            # Check additional claims
            if not self._validate_custom_claims(decoded, request_context):
                return AuthResult.FAILED

            return AuthResult.SUCCESS(decoded)

        except jwt.ExpiredSignatureError:
            return AuthResult.EXPIRED
        except jwt.InvalidSignatureError:
            await self.audit.log_security_event('INVALID_SIGNATURE', request_context)
            return AuthResult.FAILED
        except Exception as e:
            await self.audit.log_security_event('AUTHENTICATION_ERROR', {
                'error': str(e),
                'context': request_context
            })
            return AuthResult.FAILED
```

#### CVE Scanning and Vulnerability Management

##### **Automated Vulnerability Detection**
Continuous scanning for known vulnerabilities:

```python
# Automated CVE scanning pipeline
class VulnerabilityScanner:
    def __init__(self, package_manager, cve_database, notification_service):
        self.packages = package_manager
        self.cve_db = cve_database
        self.notifications = notification_service

    async def scan_for_vulnerabilities(self) -> ScanResult:
        """Comprehensive vulnerability scan"""
        results = ScanResult()

        # 1. Dependency scanning
        dependency_vulns = await self._scan_dependencies()
        results.add_vulnerabilities(dependency_vulns)

        # 2. Code scanning (SAST)
        code_vulns = await self._scan_source_code()
        results.add_vulnerabilities(code_vulns)

        # 3. Container image scanning
        image_vulns = await self._scan_container_images()
        results.add_vulnerabilities(image_vulns)

        # 4. Configuration scanning
        config_vulns = await self._scan_configurations()
        results.add_vulnerabilities(config_vulns)

        # 5. Runtime vulnerability assessment
        runtime_vulns = await self._assess_runtime_vulnerabilities()
        results.add_vulnerabilities(runtime_vulns)

        # Generate risk assessment
        results.assess_risk()

        # Send notifications for critical vulnerabilities
        await self._notify_critical_vulnerabilities(results)

        return results

    async def _scan_dependencies(self) -> list:
        """Scan Python/JavaScript dependencies for CVEs"""
        vulnerabilities = []

        # Get all dependencies with versions
        dependencies = await self.packages.get_all_dependencies()

        for dep in dependencies:
            # Query CVE database
            cves = await self.cve_db.query_vulnerabilities(
                package_name=dep['name'],
                version=dep['version']
            )

            for cve in cves:
                if self._is_vulnerable_version(dep['version'], cve['affected_versions']):
                    vulnerabilities.append({
                        'cve_id': cve['id'],
                        'package': dep['name'],
                        'severity': cve['severity'],
                        'description': cve['description'],
                        'remediation': cve.get('remediation', 'Update package')
                    })

        return vulnerabilities

    def _is_vulnerable_version(self, current_version: str, affected_ranges: list) -> bool:
        """Check if version is within vulnerable ranges"""
        current = parse_version(current_version)

        for range_spec in affected_ranges:
            if self._version_in_range(current, range_spec):
                return True

        return False
```

## 7.2 Mutual TLS Authentication

### Mutual TLS: Zero-Trust Authentication

Mutual TLS (mTLS) represents the gold standard for machine-to-machine authentication in critical infrastructure, requiring both parties to prove their identity cryptographically.

#### TLS Handshake with Mutual Authentication

##### **The mTLS Dance**
```
Client Hello (with client certificate) → Server
Server Hello (with server certificate) → Client
Client Certificate Verify → Server
Server Certificate Verify → Client
Finished → Server
Finished → Client
```

**Implementation:**
```python
# Mutual TLS configuration for vehicle agent
class MTLSConfiguration:
    def __init__(self, cert_manager, crypto_provider):
        self.cert_manager = cert_manager
        self.crypto = crypto_provider

    def get_ssl_context(self) -> ssl.SSLContext:
        """Configure SSL context for mutual TLS"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # Load server certificate and key
        context.load_cert_chain(
            certfile=self.cert_manager.get_server_cert_path(),
            keyfile=self.cert_manager.get_server_key_path()
        )

        # Load trusted CA certificates for client verification
        context.load_verify_locations(
            cafile=self.cert_manager.get_ca_cert_path()
        )

        # Configure cipher suites (prefer forward secrecy)
        context.set_ciphers(
            'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384'
        )

        # Certificate verification callback
        context.set_verify_callback(self._verify_client_certificate)

        return context

    def _verify_client_certificate(self, conn, cert, errno, depth, ok):
        """Custom certificate verification"""
        if depth == 0:  # Leaf certificate
            # Verify certificate is not revoked
            if self._is_certificate_revoked(cert):
                return False

            # Verify certificate is for vehicle authentication
            if not self._is_vehicle_certificate(cert):
                return False

            # Check certificate validity period
            if not self._is_certificate_valid(cert):
                return False

        return ok

    async def establish_secure_connection(self, host: str, port: int):
        """Establish mTLS connection with error handling"""
        context = self.get_ssl_context()

        try:
            reader, writer = await asyncio.open_connection(
                host, port, ssl=context
            )

            # Perform additional post-connection verification
            peer_cert = writer.get_extra_info('peercert')
            if not peer_cert:
                raise TLSException("No peer certificate received")

            # Log successful mutual authentication
            await self._log_mutual_auth_success(peer_cert)

            return SecureConnection(reader, writer, peer_cert)

        except ssl.SSLError as e:
            await self._log_tls_error(e)
            raise TLSException(f"TLS handshake failed: {e}")
```

#### Certificate Lifecycle Management

##### **Automated Certificate Rotation**
Preventing certificate expiration issues:

```python
class CertificateManager:
    def __init__(self, ca_service, storage_backend):
        self.ca = ca_service
        self.storage = storage_backend

    async def rotate_certificates(self):
        """Automated certificate rotation"""
        # Get certificates nearing expiration
        expiring_certs = await self._get_expiring_certificates(30)  # 30 days

        for cert_info in expiring_certs:
            try:
                # Generate new certificate
                new_cert, new_key = await self.ca.issue_certificate(
                    common_name=cert_info['cn'],
                    validity_days=365
                )

                # Store new certificate
                await self.storage.store_certificate(
                    cert_info['id'],
                    new_cert,
                    new_key
                )

                # Update configuration
                await self._update_service_configuration(
                    cert_info['service_id'],
                    new_cert,
                    new_key
                )

                # Revoke old certificate
                await self.ca.revoke_certificate(cert_info['serial'])

                # Log rotation
                await self._log_certificate_rotation(cert_info, new_cert)

            except Exception as e:
                await self._log_rotation_failure(cert_info, e)
                # Continue with other certificates

    async def _get_expiring_certificates(self, days: int) -> list:
        """Find certificates expiring within specified days"""
        all_certs = await self.storage.get_all_certificates()
        expiring = []

        for cert in all_certs:
            try:
                cert_obj = load_pem_x509_certificate(cert['pem'].encode())
                expires_in = cert_obj.not_valid_after - datetime.now()

                if expires_in.days <= days:
                    expiring.append({
                        'id': cert['id'],
                        'cn': cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                        'serial': cert_obj.serial_number,
                        'expires': cert_obj.not_valid_after,
                        'service_id': cert.get('service_id')
                    })

            except Exception as e:
                await self._log_certificate_parsing_error(cert, e)

        return expiring
```

## 7.3 Command Signing and Verification

### Command Integrity: Cryptographic Signatures

Every command sent to vehicles must be cryptographically signed to ensure authenticity, integrity, and non-repudiation. This prevents command injection attacks and provides legal accountability.

#### Digital Signature Architecture

##### **Command Signing Workflow**
```
1. Command Creation → 2. Canonical Serialization → 3. Hash Generation → 4. Private Key Signing → 5. Signature Attachment
```

**Implementation:**
```python
class CommandSigner:
    def __init__(self, key_manager, hash_algorithm=hashes.SHA256()):
        self.keys = key_manager
        self.hash_algo = hash_algorithm

    async def sign_command(self, command: dict, signer_id: str) -> SignedCommand:
        """Sign a command with digital signature"""
        # 1. Canonicalize command (ensure consistent serialization)
        canonical_command = self._canonicalize_command(command)

        # 2. Generate command hash
        command_hash = await self._generate_command_hash(canonical_command)

        # 3. Sign hash with private key
        signature = await self._sign_hash(command_hash, signer_id)

        # 4. Create signed command structure
        signed_command = SignedCommand(
            command=canonical_command,
            signature=signature,
            signer_id=signer_id,
            timestamp=datetime.utcnow(),
            algorithm=self._get_algorithm_name()
        )

        return signed_command

    def _canonicalize_command(self, command: dict) -> str:
        """Create canonical representation of command"""
        # Sort keys for consistent serialization
        sorted_command = self._sort_dict_recursively(command)

        # Use compact JSON without extra whitespace
        return json.dumps(sorted_command, separators=(',', ':'), sort_keys=True)

    def _sort_dict_recursively(self, obj):
        """Recursively sort dictionary keys"""
        if isinstance(obj, dict):
            return {k: self._sort_dict_recursively(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [self._sort_dict_recursively(item) for item in obj]
        else:
            return obj

    async def _generate_command_hash(self, canonical_command: str) -> bytes:
        """Generate cryptographic hash of command"""
        digest = hashes.Hash(self.hash_algo)
        digest.update(canonical_command.encode('utf-8'))
        return digest.finalize()

    async def _sign_hash(self, command_hash: bytes, signer_id: str) -> bytes:
        """Sign hash with appropriate private key"""
        private_key = await self.keys.get_private_key(signer_id)

        signature = private_key.sign(
            command_hash,
            padding.PSS(
                mgf=padding.MGF1(self.hash_algo),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self.hash_algo
        )

        return signature
```

#### Signature Verification Process

##### **Multi-Layer Verification**
```python
class CommandVerifier:
    def __init__(self, key_manager, audit_logger, tolerance_window=300):
        self.keys = key_manager
        self.audit = audit_logger
        self.tolerance = timedelta(seconds=tolerance_window)

    async def verify_command(self, signed_command: SignedCommand, context: dict) -> VerificationResult:
        """Verify signed command integrity and authenticity"""
        try:
            # 1. Verify signature format
            if not self._is_valid_signature_format(signed_command.signature):
                return VerificationResult.INVALID_FORMAT

            # 2. Check timestamp freshness
            if not self._is_timestamp_fresh(signed_command.timestamp):
                await self.audit.log_security_event('STALE_COMMAND', context)
                return VerificationResult.STALE

            # 3. Verify signer authorization
            if not await self._is_signer_authorized(signed_command.signer_id, signed_command.command):
                await self.audit.log_security_event('UNAUTHORIZED_SIGNER', context)
                return VerificationResult.UNAUTHORIZED

            # 4. Verify cryptographic signature
            if not await self._verify_cryptographic_signature(signed_command):
                await self.audit.log_security_event('INVALID_SIGNATURE', context)
                return VerificationResult.INVALID_SIGNATURE

            # 5. Verify command hasn't been replayed
            if await self._is_command_replayed(signed_command):
                await self.audit.log_security_event('REPLAY_ATTACK', context)
                return VerificationResult.REPLAYED

            return VerificationResult.VALID

        except Exception as e:
            await self.audit.log_security_event('VERIFICATION_ERROR', {
                'error': str(e),
                'context': context
            })
            return VerificationResult.ERROR

    async def _verify_cryptographic_signature(self, signed_command: SignedCommand) -> bool:
        """Verify the cryptographic signature"""
        # Recreate canonical command
        canonical = self._canonicalize_command(signed_command.command)

        # Generate expected hash
        expected_hash = await self._generate_command_hash(canonical)

        # Get signer's public key
        public_key = await self.keys.get_public_key(signed_command.signer_id)

        try:
            # Verify signature
            public_key.verify(
                signed_command.signature,
                expected_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def _is_timestamp_fresh(self, timestamp: datetime) -> bool:
        """Check if command timestamp is within acceptable window"""
        now = datetime.utcnow()
        time_diff = abs(now - timestamp)

        return time_diff <= self.tolerance

    async def _is_command_replayed(self, signed_command: SignedCommand) -> bool:
        """Check for command replay attacks using nonce or timestamp"""
        # Implementation would check against replay cache/database
        # This is a simplified version
        command_id = self._generate_command_id(signed_command)

        # Check if command ID has been seen recently
        if await self._is_command_id_seen_recently(command_id):
            return True

        # Store command ID for future replay detection
        await self._store_command_id(command_id, signed_command.timestamp)

        return False
```

## 7.4 PKI and Certificate Management

### Public Key Infrastructure: The Trust Foundation

PKI provides the cryptographic foundation for secure communication, authentication, and authorization in the OpenVehicleControl ecosystem.

#### Certificate Authority Architecture

##### **Hierarchical CA Structure**
```
Root CA (Offline)
├── Intermediate CA (Vehicle Certificates)
├── Intermediate CA (Service Certificates)
└── Intermediate CA (User Certificates)
```

**Implementation:**
```python
class CertificateAuthority:
    def __init__(self, root_ca_config, database):
        self.root_config = root_ca_config
        self.db = database
        self.intermediates = {}

    async def initialize_ca_hierarchy(self):
        """Initialize the CA hierarchy"""
        # Load or generate root CA
        self.root_ca = await self._load_or_generate_root_ca()

        # Create intermediate CAs
        await self._create_intermediate_cas()

        # Setup OCSP responder
        await self._initialize_ocsp_responder()

        # Setup CRL distribution
        await self._initialize_crl_distribution()

    async def issue_vehicle_certificate(self, vehicle_info: dict) -> tuple:
        """Issue certificate for vehicle authentication"""
        # Generate key pair
        private_key, public_key = await self._generate_key_pair()

        # Create certificate request
        csr = await self._create_vehicle_csr(vehicle_info, public_key)

        # Sign certificate with appropriate intermediate CA
        certificate = await self._sign_certificate(
            csr,
            self.intermediates['vehicle_ca'],
            certificate_type='vehicle'
        )

        # Store certificate metadata
        await self._store_certificate_metadata(certificate, vehicle_info)

        return certificate, private_key

    async def _create_vehicle_csr(self, vehicle_info: dict, public_key) -> x509.CertificateSigningRequest:
        """Create certificate signing request for vehicle"""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, vehicle_info.get('country', 'US')),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, vehicle_info.get('state', 'CA')),
            x509.NameAttribute(NameOID.LOCALITY_NAME, vehicle_info.get('city', 'San Francisco')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, vehicle_info.get('organization', 'Fleet Operator')),
            x509.NameAttribute(NameOID.COMMON_NAME, f"vehicle-{vehicle_info['id']}"),
        ])

        # Add vehicle-specific extensions
        extensions = [
            x509.SubjectAlternativeName([
                x509.DNSName(f"vehicle-{vehicle_info['id']}.fleet.local"),
                x509.IPAddress(ipaddress.IPv4Address(vehicle_info.get('ip_address', '192.168.1.100')))
            ]),
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            # Custom extension for vehicle type
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.3.6.1.4.1.12345.1"),  # Custom OID
                value=b'vehicle-auth'
            )
        ]

        csr = x509.CertificateSigningRequestBuilder(
            subject_name=subject
        ).add_extension(
            extensions[0], critical=False
        ).add_extension(
            extensions[1], critical=True
        ).add_extension(
            extensions[2], critical=False
        ).add_extension(
            extensions[3], critical=False
        ).sign(private_key, hashes.SHA256())

        return csr
```

#### Certificate Lifecycle Management

##### **Automated Certificate Management**
```python
class CertificateLifecycleManager:
    def __init__(self, ca_service, notification_service, monitoring_service):
        self.ca = ca_service
        self.notifications = notification_service
        self.monitoring = monitoring_service

    async def manage_certificate_lifecycle(self):
        """Main lifecycle management loop"""
        while True:
            try:
                # Check for expiring certificates
                expiring_certs = await self._find_expiring_certificates(30)  # 30 days

                for cert in expiring_certs:
                    await self._handle_expiring_certificate(cert)

                # Check for certificates to renew
                renewal_candidates = await self._find_renewal_candidates()

                for cert in renewal_candidates:
                    await self._renew_certificate(cert)

                # Update CRL and OCSP
                await self._update_revocation_info()

                # Wait before next cycle
                await asyncio.sleep(3600)  # Check hourly

            except Exception as e:
                await self.monitoring.log_error('CERT_LIFECYCLE_ERROR', str(e))
                await asyncio.sleep(300)  # Wait 5 minutes on error

    async def _handle_expiring_certificate(self, cert_info: dict):
        """Handle certificate approaching expiration"""
        days_remaining = (cert_info['not_after'] - datetime.now()).days

        # Send notifications based on urgency
        if days_remaining <= 7:
            await self.notifications.send_urgent_notification(
                'CERTIFICATE_EXPIRING_SOON',
                cert_info
            )
        elif days_remaining <= 14:
            await self.notifications.send_warning_notification(
                'CERTIFICATE_EXPIRING',
                cert_info
            )

        # Auto-renew if enabled
        if cert_info.get('auto_renew', False):
            await self._renew_certificate(cert_info)

    async def _renew_certificate(self, cert_info: dict):
        """Renew an existing certificate"""
        try:
            # Generate new certificate with same subject
            new_cert, new_key = await self.ca.renew_certificate(
                cert_info['serial_number'],
                validity_days=365
            )

            # Update certificate in systems
            await self._update_certificate_in_systems(cert_info, new_cert, new_key)

            # Revoke old certificate
            await self.ca.revoke_certificate(cert_info['serial_number'])

            await self.monitoring.log_event('CERTIFICATE_RENEWED', {
                'old_serial': cert_info['serial_number'],
                'new_serial': new_cert.serial_number
            })

        except Exception as e:
            await self.monitoring.log_error('CERTIFICATE_RENEWAL_FAILED', {
                'serial': cert_info['serial_number'],
                'error': str(e)
            })
```

## 7.5 Audit Logging and Immutable Ledger

### Immutable Audit Trails: Accountability and Compliance

Audit logging provides the foundation for security monitoring, compliance reporting, and forensic analysis. Immutability ensures that logs cannot be tampered with or deleted.

#### Immutable Logging Architecture

##### **Cryptographic Log Chain**
Each log entry is cryptographically linked to the previous entry, creating an immutable chain:

```python
class ImmutableAuditLogger:
    def __init__(self, storage_backend, crypto_provider, chain_validator):
        self.storage = storage_backend
        self.crypto = crypto_provider
        self.validator = chain_validator
        self.current_chain_hash = None

    async def log_event(self, event_type: str, event_data: dict, actor: str) -> str:
        """Log an event with immutable chaining"""
        # Create log entry
        entry = AuditLogEntry(
            id=uuid.uuid4(),
            timestamp=datetime.utcnow(),
            event_type=event_type,
            event_data=event_data,
            actor=actor,
            previous_hash=self.current_chain_hash
        )

        # Calculate entry hash
        entry_hash = await self._calculate_entry_hash(entry)

        # Update entry with its own hash
        entry.entry_hash = entry_hash

        # Store entry
        await self.storage.store_log_entry(entry)

        # Update chain hash for next entry
        self.current_chain_hash = entry_hash

        # Validate chain integrity periodically
        if await self._should_validate_chain():
            await self.validator.validate_chain_integrity()

        return entry.id

    async def _calculate_entry_hash(self, entry: AuditLogEntry) -> str:
        """Calculate cryptographic hash of log entry"""
        # Canonicalize entry data
        canonical_data = self._canonicalize_entry(entry)

        # Generate hash
        digest = hashes.Hash(hashes.SHA256())
        digest.update(canonical_data.encode('utf-8'))
        hash_bytes = digest.finalize()

        return hash_bytes.hex()

    def _canonicalize_entry(self, entry: AuditLogEntry) -> str:
        """Create canonical representation for hashing"""
        # Include all fields except the hash itself
        data = {
            'id': str(entry.id),
            'timestamp': entry.timestamp.isoformat(),
            'event_type': entry.event_type,
            'event_data': entry.event_data,
            'actor': entry.actor,
            'previous_hash': entry.previous_hash
        }

        return json.dumps(data, sort_keys=True, separators=(',', ':'))

    async def verify_log_integrity(self, from_entry_id: str = None) -> IntegrityReport:
        """Verify the integrity of the audit log chain"""
        entries = await self.storage.get_log_entries(from_entry_id)

        report = IntegrityReport()
        previous_hash = None

        for entry in entries:
            # Verify entry hash
            calculated_hash = await self._calculate_entry_hash(entry)

            if calculated_hash != entry.entry_hash:
                report.add_violation({
                    'entry_id': entry.id,
                    'expected_hash': calculated_hash,
                    'actual_hash': entry.entry_hash,
                    'violation_type': 'ENTRY_HASH_MISMATCH'
                })

            # Verify chain linkage
            if entry.previous_hash != previous_hash:
                report.add_violation({
                    'entry_id': entry.id,
                    'expected_previous': previous_hash,
                    'actual_previous': entry.previous_hash,
                    'violation_type': 'CHAIN_LINKAGE_BROKEN'
                })

            previous_hash = entry.entry_hash

        return report
```

#### Comprehensive Event Logging

##### **Security Event Categories**
```python
# Security event types and their logging requirements
SECURITY_EVENTS = {
    'AUTHENTICATION_SUCCESS': {
        'severity': 'INFO',
        'category': 'authentication',
        'retention': '1_year',
        'alert_threshold': None
    },
    'AUTHENTICATION_FAILURE': {
        'severity': 'WARNING',
        'category': 'authentication',
        'retention': '7_years',
        'alert_threshold': 5  # Alert after 5 failures
    },
    'AUTHORIZATION_FAILURE': {
        'severity': 'ERROR',
        'category': 'authorization',
        'retention': '7_years',
        'alert_threshold': 1
    },
    'COMMAND_SIGNATURE_INVALID': {
        'severity': 'CRITICAL',
        'category': 'command_integrity',
        'retention': '7_years',
        'alert_threshold': 1
    },
    'TLS_HANDSHAKE_FAILURE': {
        'severity': 'ERROR',
        'category': 'network_security',
        'retention': '1_year',
        'alert_threshold': 10
    },
    'CERTIFICATE_EXPIRING': {
        'severity': 'WARNING',
        'category': 'certificate_management',
        'retention': '7_years',
        'alert_threshold': None
    }
}

class SecurityEventLogger:
    def __init__(self, immutable_logger, alert_manager, compliance_engine):
        self.logger = immutable_logger
        self.alerts = alert_manager
        self.compliance = compliance_engine

    async def log_security_event(self, event_type: str, event_data: dict, actor: str = None):
        """Log a security event with appropriate handling"""
        event_config = SECURITY_EVENTS.get(event_type, {
            'severity': 'INFO',
            'category': 'general',
            'retention': '1_year',
            'alert_threshold': None
        })

        # Create comprehensive event data
        full_event_data = {
            'event_type': event_type,
            'severity': event_config['severity'],
            'category': event_config['category'],
            'timestamp': datetime.utcnow(),
            'actor': actor,
            'source_ip': event_data.get('source_ip'),
            'user_agent': event_data.get('user_agent'),
            'session_id': event_data.get('session_id'),
            'resource': event_data.get('resource'),
            'action': event_data.get('action'),
            'result': event_data.get('result'),
            'details': event_data
        }

        # Log to immutable audit trail
        entry_id = await self.logger.log_event(
            f'SECURITY_{event_type}',
            full_event_data,
            actor or 'system'
        )

        # Check for alert conditions
        if event_config['alert_threshold']:
            alert_count = await self._check_alert_threshold(event_type, event_config)
            if alert_count >= event_config['alert_threshold']:
                await self.alerts.trigger_security_alert(event_type, alert_count, full_event_data)

        # Update compliance metrics
        await self.compliance.update_security_metrics(event_type, full_event_data)
```

## 7.6 ISO/SAE 21434 Standards (Automotive Cybersecurity)

### ISO/SAE 21434: The Automotive Cybersecurity Standard

ISO/SAE 21434 represents the automotive industry's comprehensive framework for cybersecurity engineering, providing structured processes for secure vehicle development and operation.

#### Risk Management Framework

##### **Risk Assessment Methodology**
```python
class CybersecurityRiskAssessor:
    def __init__(self, threat_database, asset_registry, compliance_checker):
        self.threats = threat_database
        self.assets = asset_registry
        self.compliance = compliance_checker

    async def assess_vehicle_risks(self, vehicle_config: dict) -> RiskAssessment:
        """Comprehensive risk assessment per ISO/SAE 21434"""
        assessment = RiskAssessment(vehicle_config['id'])

        # 1. Asset Identification
        assets = await self._identify_assets(vehicle_config)
        assessment.add_assets(assets)

        # 2. Threat Analysis
        threats = await self._analyze_threats(assets)
        assessment.add_threats(threats)

        # 3. Vulnerability Assessment
        vulnerabilities = await self._assess_vulnerabilities(assets, threats)
        assessment.add_vulnerabilities(vulnerabilities)

        # 4. Impact Analysis
        impacts = await self._analyze_impacts(vulnerabilities)
        assessment.add_impacts(impacts)

        # 5. Risk Determination
        risks = await self._determine_risks(threats, vulnerabilities, impacts)
        assessment.add_risks(risks)

        # 6. Risk Treatment
        treatments = await self._recommend_treatments(risks)
        assessment.add_treatments(treatments)

        return assessment

    async def _identify_assets(self, vehicle_config: dict) -> list:
        """Identify cybersecurity assets in the vehicle"""
        assets = []

        # Vehicle identity and credentials
        assets.append({
            'id': 'vehicle_identity',
            'type': 'cryptographic_material',
            'value': 'high',
            'description': 'Vehicle certificates and cryptographic keys'
        })

        # Control systems
        for system in vehicle_config.get('control_systems', []):
            assets.append({
                'id': f'control_{system["id"]}',
                'type': 'control_system',
                'value': 'critical',
                'description': f'{system["name"]} control system',
                'safety_impact': system.get('safety_critical', False)
            })

        # Data assets
        assets.append({
            'id': 'telemetry_data',
            'type': 'data',
            'value': 'high',
            'description': 'Vehicle telemetry and sensor data'
        })

        return assets

    async def _analyze_threats(self, assets: list) -> list:
        """Analyze potential threats to assets"""
        threats = []

        for asset in assets:
            # Query threat database for relevant threats
            relevant_threats = await self.threats.query_threats_for_asset(asset['type'])

            for threat in relevant_threats:
                threats.append({
                    'id': f"{asset['id']}_{threat['id']}",
                    'asset_id': asset['id'],
                    'threat_type': threat['type'],
                    'likelihood': threat['likelihood'],
                    'actor': threat['actor'],
                    'description': threat['description']
                })

        return threats
```

#### Secure Development Lifecycle

##### **V-Model for Cybersecurity**
```
Requirements ←→ Integration Tests
    ↓              ↑
Design ←→ Component Tests
    ↓         ↑
Implementation ←→ Unit Tests
```

**Implementation:**
```python
class SecureDevelopmentLifecycle:
    def __init__(self, requirement_manager, design_analyzer, test_orchestrator):
        self.requirements = requirement_manager
        self.design = design_analyzer
        self.testing = test_orchestrator

    async def execute_secure_sdlc(self, project_config: dict) -> SDLCResult:
        """Execute secure development lifecycle"""
        result = SDLCResult()

        # 1. Security Requirements Definition
        security_reqs = await self._define_security_requirements(project_config)
        result.add_security_requirements(security_reqs)

        # 2. Threat Modeling and Risk Assessment
        threat_model = await self._perform_threat_modeling(project_config)
        result.add_threat_model(threat_model)

        # 3. Security Design
        security_design = await self._design_security_measures(threat_model)
        result.add_security_design(security_design)

        # 4. Secure Implementation
        implementation = await self._implement_secure_code(security_design)
        result.add_implementation(implementation)

        # 5. Security Verification and Validation
        verification = await self._verify_security_implementation(implementation)
        result.add_verification(verification)

        # 6. Security Assessment and Penetration Testing
        assessment = await self._perform_security_assessment(implementation)
        result.add_assessment(assessment)

        return result

    async def _define_security_requirements(self, project_config: dict) -> list:
        """Define security requirements based on ISO/SAE 21434"""
        requirements = []

        # Authentication requirements
        requirements.append({
            'id': 'AUTH_001',
            'category': 'authentication',
            'requirement': 'All external interfaces shall implement mutual authentication',
            'rationale': 'Prevent unauthorized access to vehicle systems',
            'verification': 'Security testing and code review'
        })

        # Authorization requirements
        requirements.append({
            'id': 'AUTHZ_001',
            'category': 'authorization',
            'requirement': 'Commands shall be validated against access control policies',
            'rationale': 'Ensure only authorized commands are executed',
            'verification': 'Automated testing and penetration testing'
        })

        # Data protection requirements
        requirements.append({
            'id': 'DATA_001',
            'category': 'data_protection',
            'requirement': 'Sensitive data shall be encrypted in transit and at rest',
            'rationale': 'Protect confidentiality of vehicle and user data',
            'verification': 'Cryptographic verification and compliance auditing'
        })

        return requirements

    async def _perform_threat_modeling(self, project_config: dict) -> ThreatModel:
        """Perform comprehensive threat modeling"""
        model = ThreatModel()

        # Identify trust boundaries
        boundaries = await self._identify_trust_boundaries(project_config)
        model.add_boundaries(boundaries)

        # Identify entry points
        entry_points = await self._identify_entry_points(project_config)
        model.add_entry_points(entry_points)

        # Identify assets
        assets = await self._identify_cyber_assets(project_config)
        model.add_assets(assets)

        # Identify threats
        threats = await self._identify_threats(boundaries, entry_points, assets)
        model.add_threats(threats)

        # Identify vulnerabilities
        vulnerabilities = await self._identify_vulnerabilities(threats)
        model.add_vulnerabilities(vulnerabilities)

        return model
```

## 7.7 GDPR Compliance and Data Anonymization

### GDPR Compliance: Privacy by Design

GDPR compliance requires comprehensive data protection measures integrated into every aspect of system design and operation.

#### Data Protection Impact Assessment

##### **Privacy Impact Assessment Framework**
```python
class GDPRComplianceManager:
    def __init__(self, data_inventory, privacy_assessor, consent_manager):
        self.data_inventory = data_inventory
        self.privacy = privacy_assessor
        self.consent = consent_manager

    async def conduct_privacy_impact_assessment(self, system_config: dict) -> PrivacyAssessment:
        """Conduct comprehensive privacy impact assessment"""
        assessment = PrivacyAssessment()

        # 1. Data Mapping and Inventory
        data_inventory = await self._map_personal_data(system_config)
        assessment.add_data_inventory(data_inventory)

        # 2. Data Processing Assessment
        processing_activities = await self._assess_processing_activities(data_inventory)
        assessment.add_processing_activities(processing_activities)

        # 3. Risk Assessment
        privacy_risks = await self._assess_privacy_risks(processing_activities)
        assessment.add_privacy_risks(privacy_risks)

        # 4. Mitigation Measures
        mitigations = await self._design_mitigation_measures(privacy_risks)
        assessment.add_mitigations(mitigations)

        # 5. Compliance Verification
        compliance_status = await self._verify_gdpr_compliance(assessment)
        assessment.set_compliance_status(compliance_status)

        return assessment

    async def _map_personal_data(self, system_config: dict) -> DataInventory:
        """Map all personal data processed by the system"""
        inventory = DataInventory()

        # Vehicle owner data
        inventory.add_data_category({
            'category': 'vehicle_owner_data',
            'data_types': ['name', 'email', 'phone', 'address'],
            'purpose': 'Vehicle registration and communication',
            'legal_basis': 'contract_performance',
            'retention_period': '7_years',
            'data_subjects': 'vehicle_owners'
        })

        # Driver data
        inventory.add_data_category({
            'category': 'driver_data',
            'data_types': ['name', 'license_number', 'biometric_data'],
            'purpose': 'Driver identification and safety monitoring',
            'legal_basis': 'legitimate_interest',
            'retention_period': '5_years',
            'data_subjects': 'drivers'
        })

        # Location data
        inventory.add_data_category({
            'category': 'location_data',
            'data_types': ['gps_coordinates', 'route_history'],
            'purpose': 'Fleet management and route optimization',
            'legal_basis': 'consent',
            'retention_period': '2_years',
            'data_subjects': 'drivers_and_owners'
        })

        return inventory

    async def _assess_processing_activities(self, data_inventory: DataInventory) -> list:
        """Assess all data processing activities"""
        activities = []

        for category in data_inventory.categories:
            activities.extend(await self._analyze_category_processing(category))

        return activities

    async def _analyze_category_processing(self, category: dict) -> list:
        """Analyze processing activities for a data category"""
        activities = []

        # Collection activity
        activities.append({
            'activity': f'collect_{category["category"]}',
            'data_category': category['category'],
            'processing_type': 'collection',
            'purpose': category['purpose'],
            'legal_basis': category['legal_basis'],
            'data_volume': await self._estimate_data_volume(category),
            'risk_level': await self._assess_processing_risk(category, 'collection')
        })

        # Storage activity
        activities.append({
            'activity': f'store_{category["category"]}',
            'data_category': category['category'],
            'processing_type': 'storage',
            'purpose': category['purpose'],
            'retention_period': category['retention_period'],
            'risk_level': await self._assess_processing_risk(category, 'storage')
        })

        # Processing activity
        activities.append({
            'activity': f'process_{category["category"]}',
            'data_category': category['category'],
            'processing_type': 'processing',
            'purpose': category['purpose'],
            'automated_decisions': await self._check_automated_decisions(category),
            'risk_level': await self._assess_processing_risk(category, 'processing')
        })

        return activities
```

#### Data Anonymization and Pseudonymization

##### **Privacy-Preserving Data Processing**
```python
class DataAnonymizationEngine:
    def __init__(self, crypto_provider, privacy_policies):
        self.crypto = crypto_provider
        self.policies = privacy_policies

    async def anonymize_vehicle_data(self, raw_data: dict, purpose: str) -> dict:
        """Anonymize vehicle data based on processing purpose"""
        anonymized = {}

        # Apply anonymization based on data type and purpose
        for key, value in raw_data.items():
            if key in ['license_plate', 'vehicle_vin']:
                anonymized[key] = await self._pseudonymize_identifier(value, purpose)
            elif key in ['driver_name', 'owner_name']:
                anonymized[key] = await self._anonymize_personal_name(value, purpose)
            elif key == 'location':
                anonymized[key] = await self._generalize_location(value, purpose)
            elif key == 'telemetry_data':
                anonymized[key] = await self._aggregate_telemetry(value, purpose)
            else:
                anonymized[key] = value

        return anonymized

    async def _pseudonymize_identifier(self, identifier: str, purpose: str) -> str:
        """Create pseudonym for identifiers"""
        policy = self.policies.get_pseudonymization_policy(purpose)

        if policy['method'] == 'cryptographic_hash':
            # Create consistent pseudonym using salt
            salt = policy['salt']
            hash_input = f"{identifier}{salt}"
            pseudonym = await self.crypto.hash_string(hash_input)
            return pseudonym[:16]  # Truncate for readability

        elif policy['method'] == 'tokenization':
            # Replace with token
            return await self._generate_token(identifier)

    async def _anonymize_personal_name(self, name: str, purpose: str) -> str:
        """Anonymize personal names"""
        policy = self.policies.get_anonymization_policy('personal_names', purpose)

        if policy['method'] == 'suppression':
            return '[REDACTED]'
        elif policy['method'] == 'generalization':
            # Convert to initials or categories
            parts = name.split()
            if len(parts) >= 2:
                return f"{parts[0][0]}.{parts[-1][0]}."
            else:
                return f"{name[0]}."
        elif policy['method'] == 'pseudonymization':
            return await self._pseudonymize_identifier(name, purpose)

    async def _generalize_location(self, location: dict, purpose: str) -> dict:
        """Generalize location data for privacy"""
        policy = self.policies.get_location_privacy_policy(purpose)

        precision = policy.get('precision', 'city')

        if precision == 'country':
            return {'country': location.get('country')}
        elif precision == 'region':
            return {
                'country': location.get('country'),
                'region': location.get('region')
            }
        elif precision == 'city':
            return {
                'country': location.get('country'),
                'region': location.get('region'),
                'city': location.get('city')
            }
        else:
            # Full precision
            return location

    async def _aggregate_telemetry(self, telemetry_data: list, purpose: str) -> dict:
        """Aggregate telemetry data to reduce individual identifiability"""
        if not telemetry_data:
            return {}

        policy = self.policies.get_aggregation_policy(purpose)

        # Calculate aggregates
        aggregated = {
            'count': len(telemetry_data),
            'time_range': {
                'start': min(t['timestamp'] for t in telemetry_data),
                'end': max(t['timestamp'] for t in telemetry_data)
            },
            'averages': {},
            'ranges': {}
        }

        # Aggregate numeric fields
        numeric_fields = ['speed', 'battery_level', 'temperature']
        for field in numeric_fields:
            values = [t.get(field) for t in telemetry_data if t.get(field) is not None]
            if values:
                aggregated['averages'][field] = sum(values) / len(values)
                aggregated['ranges'][field] = {
                    'min': min(values),
                    'max': max(values)
                }

        return aggregated
```

This comprehensive security and compliance framework ensures that OpenVehicleControl meets the highest standards for cybersecurity, data protection, and regulatory compliance while maintaining the flexibility needed for diverse operational environments.
