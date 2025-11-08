# 🧩 Chapter 6: Protocols and Standards

## 6.1 List of Supported Standards

### Standards Ecosystem: The Language of Connected Vehicles

Just as human societies developed common languages and protocols for communication, the automotive industry has established a comprehensive set of standards that enable interoperability between vehicles, infrastructure, and services. OpenVehicleControl embraces this standards ecosystem, implementing support for the most critical protocols while maintaining flexibility for future extensions.

#### Core Standards Categories

The system supports standards across five fundamental categories:

##### **1. Vehicle Communication Protocols**
- **CAN (Controller Area Network)**: ISO 11898 - Internal vehicle network communication
- **CAN FD (CAN with Flexible Data-Rate)**: ISO 11898-1 - Enhanced CAN with higher bandwidth
- **LIN (Local Interconnect Network)**: ISO 17987 - Low-cost vehicle networking
- **FlexRay**: ISO 17458 - High-speed, fault-tolerant networking for safety-critical systems

##### **2. Diagnostic and Service Protocols**
- **OBD-II (On-Board Diagnostics II)**: SAE J1979 - Standardized vehicle diagnostics
- **UDS (Unified Diagnostic Services)**: ISO 14229 - Advanced diagnostic services
- **WWH-OBD (Worldwide Harmonized OBD)**: Global diagnostic requirements
- **DoIP (Diagnostic over IP)**: ISO 13400 - Internet Protocol-based diagnostics

##### **3. Electric Vehicle Standards**
- **ISO 15118**: Plug & Charge communication for electric vehicles
- **IEC 61851**: Conductive charging system for electric vehicles
- **IEC 62196**: Plugs, socket-outlets, and couplers for EV charging
- **CHAdeMO**: Japanese DC fast charging protocol

##### **4. Charging Infrastructure Protocols**
- **OCPP (Open Charge Point Protocol)**: 1.6 and 2.0.1 - Charging station management
- **IEC 63110**: Protocol for the management of EV charging and discharging
- **ISO 14443**: Contactless smart card standards for payment

##### **5. IoT and Data Communication**
- **MQTT (Message Queuing Telemetry Transport)**: OASIS standard - Lightweight messaging
- **CoAP (Constrained Application Protocol)**: RFC 7252 - Web transfer protocol for IoT
- **LwM2M (Lightweight Machine-to-Machine)**: OMA specification - Device management

### Standards Compliance Matrix

#### Implementation Status Overview

| Standard | Category | Implementation Level | Notes |
|----------|----------|---------------------|-------|
| CAN 2.0B | Vehicle Network | ✅ Full | Base vehicle communication |
| CAN FD | Vehicle Network | ✅ Full | High-speed data transmission |
| OBD-II | Diagnostics | ✅ Full | All standard PIDs supported |
| UDS | Diagnostics | ✅ Full | Extended diagnostics and reprogramming |
| ISO 15118 | EV Charging | ✅ Full | Plug & Charge implementation |
| OCPP 1.6 | Charging | ✅ Full | Legacy charging station support |
| OCPP 2.0.1 | Charging | ✅ Full | Modern charging infrastructure |
| MQTT 5.0 | IoT Messaging | ✅ Full | Complete feature implementation |
| WebSocket | Real-time | ✅ Full | RFC 6455 compliant |
| REST API | Web Services | ✅ Full | OpenAPI 3.0 specification |

## 6.2 OBD-II and CAN-FD

### OBD-II: The Universal Vehicle Diagnostic Language

OBD-II represents the standardized diagnostic interface that transformed automotive maintenance from proprietary dealer tools to universal access. Understanding OBD-II requires recognizing it as both a protocol and a philosophy of openness in vehicle systems.

#### OBD-II Protocol Architecture

##### **Physical Layer: The Hardware Interface**
OBD-II defines the physical connection between diagnostic tools and vehicles:

**Connector Specifications:**
- **16-pin DLC (Data Link Connector)**: Standardized location and pin assignments
- **Pin 4 & 5**: Ground connections for signal reference
- **Pin 6**: CAN High (for CAN-based systems)
- **Pin 7**: ISO 9141-2 K-line (legacy systems)
- **Pin 10**: CAN Low (for CAN-based systems)
- **Pin 14**: ISO 9141-2 L-line (legacy systems)
- **Pin 15**: Vehicle battery positive voltage
- **Pin 16**: Vehicle battery positive voltage (main power)

**Communication Protocols:**
- **CAN (500kbps)**: Primary protocol for modern vehicles
- **ISO 9141-2**: Legacy protocol for older vehicles
- **J1850 PWM/VPW**: North American manufacturer-specific protocols
- **ISO 14230 (KWP2000)**: European diagnostic protocol

##### **Application Layer: Parameter IDs (PIDs)**

OBD-II defines standardized parameter identifiers that provide access to vehicle systems:

```python
# Core OBD-II PID definitions with formulas
OBD_II_PIDS = {
    # Powertrain PIDs
    0x04: {
        'name': 'Calculated Engine Load',
        'description': 'Engine load calculated by ECM',
        'bytes': 1,
        'min': 0, 'max': 100,
        'units': '%',
        'formula': lambda x: x * 100 / 255
    },
    0x05: {
        'name': 'Engine Coolant Temperature',
        'description': 'Temperature of engine coolant',
        'bytes': 1,
        'min': -40, 'max': 215,
        'units': '°C',
        'formula': lambda x: x - 40
    },
    0x0B: {
        'name': 'Intake Manifold Absolute Pressure',
        'description': 'Absolute pressure in intake manifold',
        'bytes': 1,
        'min': 0, 'max': 255,
        'units': 'kPa',
        'formula': lambda x: x
    },
    0x0C: {
        'name': 'Engine RPM',
        'description': 'Engine revolutions per minute',
        'bytes': 2,
        'min': 0, 'max': 16383.75,
        'units': 'rpm',
        'formula': lambda x: x / 4
    },
    0x0D: {
        'name': 'Vehicle Speed',
        'description': 'Speed of vehicle',
        'bytes': 1,
        'min': 0, 'max': 255,
        'units': 'km/h',
        'formula': lambda x: x
    },

    # Electric Vehicle PIDs (ISO 15031-5)
    0x42: {
        'name': 'Control Module Voltage',
        'description': 'Voltage of control module',
        'bytes': 2,
        'min': 0, 'max': 655.35,
        'units': 'V',
        'formula': lambda x: x / 1000
    },
    0x43: {
        'name': 'Absolute Load Value',
        'description': 'Absolute load value',
        'bytes': 2,
        'min': 0, 'max': 25700,
        'units': '%',
        'formula': lambda x: x * 100 / 255
    }
}
```

#### OBD-II Message Structure

##### **Request Format**
OBD-II requests follow a specific format for querying vehicle data:

```
Byte 0: Mode (Service) - Defines the type of request
Byte 1: PID (Parameter ID) - Specific parameter to query
Bytes 2+: Additional data (if required)
```

**Service Modes:**
- **Mode $01**: Show current data - Real-time sensor readings
- **Mode $02**: Show freeze frame data - Stored data from DTC trigger
- **Mode $03**: Show stored Diagnostic Trouble Codes (DTCs)
- **Mode $04**: Clear Diagnostic Trouble Codes and stored values
- **Mode $05**: Test results, oxygen sensor monitoring
- **Mode $06**: Test results, other component/system monitoring
- **Mode $07**: Show pending Diagnostic Trouble Codes
- **Mode $08**: Control operation of on-board component/system
- **Mode $09**: Request vehicle information
- **Mode $0A**: Permanent Diagnostic Trouble Codes

##### **Response Format**
Vehicle responses include echo bytes and requested data:

```
Byte 0: Mode (Service) + 0x40 - Response indicator
Byte 1: PID - Echo of requested parameter
Bytes 2+: Data bytes (varies by PID)
```

#### CAN-FD: Enhanced Vehicle Communication

##### **CAN vs CAN-FD Comparison**

| Feature | CAN 2.0 | CAN FD |
|---------|---------|--------|
| Max Data Rate | 1 Mbps | 5-8 Mbps |
| Max Payload | 8 bytes | 64 bytes |
| Backward Compatible | N/A | Yes |
| Arbitration Rate | Same as data | Up to 1 Mbps |
| Use Cases | Standard | High-bandwidth sensors |

##### **CAN-FD Implementation**
```python
# CAN-FD message handling
class CANFDHandler:
    def __init__(self, interface):
        self.interface = interface
        self.fd_supported = False

    async def detect_canfd_support(self) -> bool:
        """Detect if CAN-FD is supported by the network"""
        # Send CAN-FD probe message
        probe_msg = can.Message(
            arbitration_id=0x123,
            data=[0xFF] * 64,  # Maximum payload
            is_fd=True,
            bitrate_switch=True
        )

        try:
            await self.interface.send(probe_msg)
            response = await self.interface.receive(timeout=1.0)
            self.fd_supported = True
            return True
        except:
            self.fd_supported = False
            return False

    async def send_large_data(self, arbitration_id: int, data: bytes):
        """Send large data payloads using CAN-FD"""
        if not self.fd_supported:
            # Fall back to CAN 2.0 with fragmentation
            await self._send_fragmented(arbitration_id, data)
            return

        # Send as single CAN-FD frame
        if len(data) <= 64:
            msg = can.Message(
                arbitration_id=arbitration_id,
                data=data,
                is_fd=True,
                bitrate_switch=True
            )
            await self.interface.send(msg)
        else:
            # Fragment large data
            await self._send_fragmented_fd(arbitration_id, data)
```

## 6.3 UDS (Unified Diagnostic Services)

### UDS: Advanced Diagnostic Services Architecture

UDS represents the evolution from basic OBD-II diagnostics to comprehensive vehicle system management, enabling not just monitoring but also active system control and reprogramming.

#### UDS Protocol Stack

##### **OSI Model Mapping**
UDS operates at multiple layers of the OSI model:

- **Physical Layer**: CAN, FlexRay, Ethernet (DoIP)
- **Data Link Layer**: Transport protocols for segmentation
- **Network Layer**: Addressing and routing
- **Application Layer**: UDS services and data formats

##### **Session Management**
UDS operates within diagnostic sessions that define available services:

```python
# UDS Session types
UDS_SESSIONS = {
    0x01: {
        'name': 'Default Session',
        'description': 'Normal vehicle operation',
        'services': ['diagnostic', 'read_data', 'read_dtc']
    },
    0x02: {
        'name': 'Programming Session',
        'description': 'Firmware update and reprogramming',
        'services': ['diagnostic', 'programming', 'security']
    },
    0x03: {
        'name': 'Extended Diagnostic Session',
        'description': 'Advanced diagnostics and testing',
        'services': ['diagnostic', 'testing', 'calibration']
    },
    0x04: {
        'name': 'Safety System Diagnostic Session',
        'description': 'Safety-critical system diagnostics',
        'services': ['diagnostic', 'safety_testing']
    }
}

class UDSSessionManager:
    def __init__(self, transport_layer):
        self.transport = transport_layer
        self.current_session = 0x01  # Default session
        self.session_timeout = 5000  # 5 seconds

    async def change_session(self, session_type: int) -> bool:
        """Change diagnostic session"""
        request = UDSMessage(
            service_id=0x10,  # DiagnosticSessionControl
            sub_function=session_type
        )

        response = await self.transport.send_and_receive(request)

        if response.service_id == 0x50 and response.sub_function == session_type:
            self.current_session = session_type
            # Reset session timer
            await self._reset_session_timer()
            return True

        return False

    async def _reset_session_timer(self):
        """Reset session timeout timer"""
        # Implementation would set up timer to return to default session
        pass
```

#### UDS Services Implementation

##### **Core Diagnostic Services**

**Service 0x10: Diagnostic Session Control**
```python
async def diagnostic_session_control(self, session_type: int):
    """Control diagnostic session"""
    request = [0x10, session_type]
    response = await self._send_uds_request(request)

    if response[0] == 0x50:  # Positive response
        return {
            'session_type': response[1],
            'session_parameter_record': response[2:] if len(response) > 2 else []
        }
    else:
        raise UDSException(f"Session control failed: {response[0]}")
```

**Service 0x11: ECU Reset**
```python
async def ecu_reset(self, reset_type: int):
    """Reset Electronic Control Unit"""
    request = [0x11, reset_type]
    response = await self._send_uds_request(request)

    if response[0] == 0x51:  # Positive response
        # ECU will reset after sending response
        return {'reset_type': response[1]}
    else:
        raise UDSException(f"ECU reset failed: {response[0]}")
```

**Service 0x22: Read Data by Identifier**
```python
async def read_data_by_identifier(self, identifier: int) -> bytes:
    """Read data identified by DID"""
    request = [
        0x22,  # Service ID
        (identifier >> 8) & 0xFF,  # DID high byte
        identifier & 0xFF  # DID low byte
    ]

    response = await self._send_uds_request(request)

    if response[0] == 0x62:  # Positive response
        # Verify DID matches
        response_did = (response[1] << 8) | response[2]
        if response_did == identifier:
            return response[3:]  # Return data
        else:
            raise UDSException("DID mismatch in response")

    raise UDSException(f"Read DID failed: {response[0]}")
```

**Service 0x27: Security Access**
```python
async def security_access(self, access_type: int) -> bytes:
    """Perform security access (unlock ECU)"""
    # Request seed
    seed_request = [0x27, access_type]
    seed_response = await self._send_uds_request(seed_request)

    if seed_response[0] != 0x67:
        raise UDSException(f"Security access seed request failed: {seed_response[0]}")

    seed = seed_response[2:6]  # Extract seed bytes

    # Calculate key (implementation-specific algorithm)
    key = await self._calculate_security_key(seed, access_type)

    # Send key
    key_request = [0x27, access_type + 1] + list(key)
    key_response = await self._send_uds_request(key_request)

    if key_response[0] == 0x67 and key_response[1] == (access_type + 1):
        return key_response[2:] if len(key_response) > 2 else b''
    else:
        raise UDSException(f"Security access key failed: {key_response[0]}")

async def _calculate_security_key(self, seed: bytes, access_type: int) -> bytes:
    """Calculate security key from seed (vehicle-specific algorithm)"""
    # This is a simplified example - real implementations vary by manufacturer
    # and often involve cryptographic operations

    # XOR-based algorithm (example only)
    key = bytearray(4)
    for i in range(4):
        key[i] = seed[i] ^ 0xAA  # Example transformation

    return bytes(key)
```

**Service 0x31: Routine Control**
```python
async def routine_control(self, routine_id: int, control_type: int, options: bytes = b'') -> bytes:
    """Control diagnostic routines"""
    request = [
        0x31,  # Service ID
        control_type,  # Start/Stop/Result
        (routine_id >> 8) & 0xFF,  # Routine ID high
        routine_id & 0xFF  # Routine ID low
    ] + list(options)

    response = await self._send_uds_request(request)

    if response[0] == 0x71:  # Positive response
        return response[3:]  # Routine results
    else:
        raise UDSException(f"Routine control failed: {response[0]}")
```

##### **Data Transmission Services**

**Service 0x2E: Write Data by Identifier**
```python
async def write_data_by_identifier(self, identifier: int, data: bytes):
    """Write data to specified identifier"""
    request = [
        0x2E,  # Service ID
        (identifier >> 8) & 0xFF,  # DID high byte
        identifier & 0xFF  # DID low byte
    ] + list(data)

    response = await self._send_uds_request(request)

    if response[0] == 0x6E:  # Positive response
        return True
    else:
        raise UDSException(f"Write DID failed: {response[0]}")
```

## 6.4 ISO 15118 and IEC 61851 (EV Charging)

### ISO 15118: The Smart Charging Revolution

ISO 15118 represents the convergence of automotive and electrical engineering standards, enabling electric vehicles to communicate intelligently with charging infrastructure for optimized energy management.

#### ISO 15118 Protocol Architecture

##### **Communication Layers**
ISO 15118 defines a complete communication stack for EV charging:

**Physical Layer:**
- **PLC (Power Line Communication)**: Using HomePlug Green PHY
- **WLAN**: IEEE 802.11 based wireless communication
- **NFC**: ISO/IEC 14443 for proximity detection

**Network Layer:**
- **IPv6**: Internet Protocol version 6 for addressing
- **TCP/UDP**: Transport protocols for reliable communication

**Application Layer:**
- **V2G (Vehicle-to-Grid)**: XML-based messaging protocol
- **TLS**: Transport Layer Security for encryption
- **X.509**: Certificate-based authentication

##### **Message Exchange Patterns**

ISO 15118 defines structured message exchanges between EV and charging station:

**Session Setup Phase:**
```xml
<!-- EV → SECC: Session Setup Request -->
<v2g:SessionSetupReq>
    <v2g:EVCCID>EV123456789</v2g:EVCCID>
</v2g:SessionSetupReq>

<!-- SECC → EV: Session Setup Response -->
<v2g:SessionSetupRes>
    <v2g:ResponseCode>OK</v2g:ResponseCode>
    <v2g:EVSEID>SECC123456789</v2g:EVSEID>
    <v2g:EVSETimeStamp>1640995200</v2g:EVSETimeStamp>
</v2g:SessionSetupRes>
```

**Service Discovery Phase:**
```xml
<!-- EV → SECC: Service Discovery Request -->
<v2g:ServiceDiscoveryReq>
    <v2g:ServiceScope>AC_DC_Charging</v2g:ServiceScope>
</v2g:ServiceDiscoveryReq>

<!-- SECC → EV: Service Discovery Response -->
<v2g:ServiceDiscoveryRes>
    <v2g:ResponseCode>OK</v2g:ResponseCode>
    <v2g:PaymentOptionList>
        <v2g:PaymentOption>ExternalPayment</v2g:PaymentOption>
        <v2g:PaymentOption>Contract</v2g:PaymentOption>
    </v2g:PaymentOptionList>
    <v2g:ChargeService>
        <v2g:ServiceID>1</v2g:ServiceID>
        <v2g:ServiceName>AC_DC_Charging</v2g:ServiceName>
        <v2g:ServiceCategory>EVCharging</v2g:ServiceCategory>
    </v2g:ChargeService>
</v2g:ServiceDiscoveryRes>
```

#### Charging Process Implementation

##### **Plug & Charge Sequence**
```python
class ISO15118Handler:
    def __init__(self, communication_interface):
        self.comm = communication_interface
        self.session_id = None
        self.contract_id = None

    async def execute_plug_and_charge(self, evcc_id: str) -> dict:
        """Complete Plug & Charge sequence"""
        results = {}

        # 1. Session Setup
        results['session'] = await self._session_setup(evcc_id)
        self.session_id = results['session']['session_id']

        # 2. Service Discovery
        results['services'] = await self._service_discovery()

        # 3. Payment Service Selection
        results['payment'] = await self._payment_service_selection()

        # 4. Certificate Installation (if needed)
        if not await self._certificate_check():
            results['certificate'] = await self._certificate_installation()

        # 5. Authorization
        results['authorization'] = await self._authorization()

        # 6. Charge Parameter Discovery
        results['charge_params'] = await self._charge_parameter_discovery()

        # 7. Power Delivery (cable check and pre-charge)
        results['power_delivery'] = await self._power_delivery()

        # 8. Charging
        results['charging'] = await self._charging_loop()

        # 9. Session Stop
        results['stop'] = await self._session_stop()

        return results

    async def _session_setup(self, evcc_id: str) -> dict:
        """Establish communication session"""
        request = SessionSetupReq(evcc_id=evcc_id)

        response = await self.comm.send_and_receive(request)

        if response.response_code != ResponseCode.OK:
            raise ISO15118Exception(f"Session setup failed: {response.response_code}")

        return {
            'session_id': response.session_id,
            'evse_id': response.evse_id,
            'timestamp': response.evse_timestamp
        }

    async def _authorization(self) -> dict:
        """Perform authorization using certificates"""
        # Get contract certificate chain
        cert_chain = await self._get_contract_certificates()

        request = AuthorizationReq(
            id=AuthorizationIdType.contract,
            certificate_chain=cert_chain
        )

        response = await self.comm.send_and_receive(request)

        if response.response_code != ResponseCode.OK:
            raise ISO15118Exception(f"Authorization failed: {response.response_code}")

        self.contract_id = response.contract_id

        return {
            'contract_id': response.contract_id,
            'certificate_status': response.certificate_status
        }
```

#### IEC 61851: Charging Infrastructure Standards

##### **Charging Modes**
IEC 61851 defines four charging modes based on safety and control:

**Mode 1: Slow charging from domestic socket**
- No communication between EV and charging station
- Maximum current: 16A (single-phase), 10A (three-phase)
- Protective earth conductor required

**Mode 2: Slow charging with cable control**
- EV controls charging through control pilot
- Maximum current: 32A
- In-cable protection device (ICPD) required

**Mode 3: Fast charging with station control**
- Charging station controls charging process
- Communication via control pilot
- Maximum current: 250A (three-phase)

**Mode 4: DC fast charging**
- External charger required
- High power delivery (up to 350kW)
- Digital communication required

##### **Control Pilot Signal**
The control pilot (CP) signal provides essential communication:

```python
class ControlPilotDecoder:
    def __init__(self, adc_interface):
        self.adc = adc_interface
        self.state_machine = ChargingStateMachine()

    async def decode_cp_signal(self) -> dict:
        """Decode control pilot signal"""
        voltage = await self.adc.read_voltage()
        frequency = await self.adc.measure_frequency()
        duty_cycle = await self.adc.measure_duty_cycle()

        # Decode charging state
        state = self._decode_state(voltage, frequency, duty_cycle)

        # Decode maximum current (for Mode 3)
        max_current = self._decode_max_current(duty_cycle)

        return {
            'state': state,
            'max_current': max_current,
            'voltage': voltage,
            'frequency': frequency,
            'duty_cycle': duty_cycle
        }

    def _decode_state(self, voltage: float, frequency: float, duty_cycle: float) -> str:
        """Decode charging state from CP signal"""
        if abs(voltage - 12) < 1:  # +12V
            return 'ready'  # Ready to charge
        elif abs(voltage - 9) < 1:  # +9V
            return 'charging'  # Vehicle charging
        elif abs(voltage - 6) < 1:  # +6V
            return 'error'  # Error state
        elif abs(voltage - 3) < 1:  # +3V
            return 'connected'  # Connected, not ready
        elif abs(voltage + 12) < 1:  # -12V
            return 'ventilation'  # Ventilation required
        else:
            return 'disconnected'  # Not connected

    def _decode_max_current(self, duty_cycle: float) -> float:
        """Decode maximum current from duty cycle"""
        # IEC 61851-1 duty cycle encoding
        if duty_cycle < 3:
            return 0  # Charging not allowed
        elif duty_cycle <= 7:
            return (duty_cycle - 1) * 0.6  # 0.6A resolution
        elif duty_cycle <= 10:
            return 6 + (duty_cycle - 8) * 2.5  # 2.5A resolution
        elif duty_cycle <= 85:
            return 13 + (duty_cycle - 11) * 0.6  # 0.6A resolution
        elif duty_cycle <= 96:
            return 62 + (duty_cycle - 86) * 2.5  # 2.5A resolution
        else:
            return 80  # Maximum current
```

## 6.5 OCPP 1.6 / 2.0.1 (Charging Stations)

### OCPP: The Language of Charging Networks

OCPP (Open Charge Point Protocol) serves as the universal language for charging station management, enabling interoperability between charging stations and central management systems regardless of manufacturer.

#### OCPP 1.6: Established Standard

##### **Protocol Architecture**
OCPP 1.6 uses SOAP over WebSocket for communication:

```xml
<!-- Boot Notification -->
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Body>
        <cs:BootstrapNotificationRequest xmlns:cs="urn://Ocpp/Cs/2012/06/">
            <cs:chargePointVendor>Acme Corp</cs:chargePointVendor>
            <cs:chargePointModel>SuperCharger 3000</cs:chargePointModel>
            <cs:chargePointSerialNumber>SC3000-001</cs:chargePointSerialNumber>
            <cs:chargeBoxSerialNumber>CB001</cs:chargeBoxSerialNumber>
            <cs:firmwareVersion>1.2.3</cs:firmwareVersion>
            <cs:iccid>89012345678901234567</cs:iccid>
            <cs:imsi>310150123456789</cs:imsi>
            <cs:meterType>Analog</cs:meterType>
            <cs:meterSerialNumber>METER001</cs:meterSerialNumber>
        </cs:BootstrapNotificationRequest>
    </soap:Body>
</soap:Envelope>
```

##### **Core Operations**
OCPP 1.6 defines essential charging station operations:

**Boot Notification:**
```python
async def send_boot_notification(self):
    """Send boot notification to central system"""
    boot_request = {
        'chargePointVendor': self.vendor,
        'chargePointModel': self.model,
        'chargePointSerialNumber': self.serial,
        'chargeBoxSerialNumber': self.box_serial,
        'firmwareVersion': self.firmware_version,
        'iccid': self.iccid,
        'imsi': self.imsi,
        'meterType': self.meter_type,
        'meterSerialNumber': self.meter_serial
    }

    response = await self.call_operation('BootNotification', boot_request)

    # Handle response
    self.status = response.get('status', 'Rejected')
    self.heartbeat_interval = response.get('heartbeatInterval', 300)
```

**Authorize Request:**
```python
async def authorize_id_tag(self, id_tag: str) -> dict:
    """Authorize RFID tag or contract"""
    request = {'idTag': id_tag}

    response = await self.call_operation('Authorize', request)

    return {
        'authorized': response['idTagInfo']['status'] == 'Accepted',
        'parent_id_tag': response['idTagInfo'].get('parentIdTag'),
        'expiry_date': response['idTagInfo'].get('expiryDate'),
        'group_id_tag': response['idTagInfo'].get('groupIdTag')
    }
```

**Start Transaction:**
```python
async def start_transaction(self, connector_id: int, id_tag: str, meter_start: int) -> dict:
    """Start charging transaction"""
    request = {
        'connectorId': connector_id,
        'idTag': id_tag,
        'timestamp': datetime.utcnow().isoformat(),
        'meterStart': meter_start,
        'reservationId': self.reservation_id  # if reserved
    }

    response = await self.call_operation('StartTransaction', request)

    if response['idTagInfo']['status'] == 'Accepted':
        self.transaction_id = response['transactionId']
        return {
            'transaction_id': self.transaction_id,
            'status': 'started'
        }
    else:
        return {
            'status': 'rejected',
            'reason': response['idTagInfo']['status']
        }
```

#### OCPP 2.0.1: Modern Charging Infrastructure

##### **Enhanced Features**
OCPP 2.0.1 introduces significant improvements:

- **JSON-based messaging**: More efficient than SOAP
- **Smart charging**: Integration with energy management systems
- **ISO 15118 support**: Plug & Charge integration
- **Enhanced security**: Improved authentication mechanisms
- **Transaction event logging**: Better transaction tracking

##### **JSON Message Format**
```json
{
    "messageTypeId": 2,
    "uniqueId": "123456789",
    "action": "BootNotification",
    "payload": {
        "reason": "PowerUp",
        "chargingStation": {
            "serialNumber": "SC3000-001",
            "model": "SuperCharger 3000",
            "vendorName": "Acme Corp",
            "firmwareVersion": "2.0.1",
            "modem": {
                "iccid": "89012345678901234567",
                "imsi": "310150123456789"
            }
        }
    }
}
```

##### **Smart Charging Integration**
OCPP 2.0.1 enables sophisticated energy management:

```python
class SmartChargingController:
    def __init__(self, ocpp_handler):
        self.ocpp = ocpp_handler
        self.charging_profiles = {}

    async def set_charging_profile(self, profile_id: int, profile: dict):
        """Set charging profile for smart charging"""
        request = {
            'evseId': profile.get('evseId', 0),
            'chargingProfileId': profile_id,
            'stackLevel': profile.get('stackLevel', 0),
            'chargingProfilePurpose': profile.get('purpose', 'TxProfile'),
            'chargingProfileKind': profile.get('kind', 'Absolute'),
            'chargingSchedule': profile['schedule']
        }

        response = await self.ocpp.call_operation('SetChargingProfile', request)

        if response['status'] == 'Accepted':
            self.charging_profiles[profile_id] = profile
            return True

        return False

    async def get_composite_schedule(self, duration: int, evse_id: int = 0) -> dict:
        """Get composite charging schedule"""
        request = {
            'duration': duration,
            'evseId': evse_id,
            'chargingRateUnit': 'A'  # or 'W'
        }

        response = await self.ocpp.call_operation('GetCompositeSchedule', request)

        return {
            'schedule': response.get('chargingSchedule'),
            'connector_id': response.get('connectorId', evse_id)
        }
```

## 6.6 MQTT 5.0 and QoS

### MQTT: The IoT Communication Standard

MQTT has become the de facto standard for IoT communication due to its lightweight design, efficient bandwidth usage, and reliable message delivery guarantees.

#### MQTT 5.0 Protocol Features

##### **Enhanced Features over MQTT 3.1.1**
MQTT 5.0 introduces significant improvements:

- **User Properties**: Custom metadata in messages
- **Message Expiry**: Automatic message cleanup
- **Topic Aliases**: Reduced bandwidth for frequent topics
- **Shared Subscriptions**: Load balancing across subscribers
- **Request/Response**: RPC-style communication patterns
- **Session Expiry**: Persistent sessions with timeouts
- **Reason Codes**: Detailed error reporting

##### **Message Structure**
MQTT messages consist of a fixed header, variable header, and payload:

```
Fixed Header (2-5 bytes):
  - Message Type (4 bits)
  - DUP flag (1 bit)
  - QoS Level (2 bits)
  - RETAIN flag (1 bit)
  - Remaining Length (variable)

Variable Header (varies by message type):
  - Packet Identifier (for QoS > 0)
  - Topic Name
  - Properties

Payload (optional):
  - Application data
```

#### Quality of Service (QoS) Levels

##### **QoS 0: At Most Once Delivery**
Fire-and-forget messaging with no guarantees:

```python
# Publisher
await client.publish('vehicle/status', status_data, qos=0)

# Subscriber receives message once or not at all
# No acknowledgment required
```

**Use Cases:**
- Real-time sensor data where loss is acceptable
- Frequent status updates
- Non-critical notifications

##### **QoS 1: At Least Once Delivery**
Guaranteed delivery with possible duplicates:

```python
# Publisher sends message
packet_id = await client.publish('vehicle/command', command_data, qos=1)

# Broker acknowledges receipt
# Publisher resends if no acknowledgment within timeout

# Subscriber processes message and sends acknowledgment
# Duplicate messages possible if acknowledgment lost
```

**Use Cases:**
- Important commands that must be delivered
- Configuration changes
- Event notifications

##### **QoS 2: Exactly Once Delivery**
Guaranteed single delivery with higher overhead:

```python
# Four-step handshake:
# 1. PUBLISH (QoS 2) - Publisher → Broker
# 2. PUBREC - Broker → Publisher (acknowledgment)
# 3. PUBREL - Publisher → Broker (release)
# 4. PUBCOMP - Broker → Publisher (complete)
```

**Use Cases:**
- Critical safety commands
- Financial transactions
- Firmware updates

#### Advanced MQTT Features

##### **Last Will and Testament (LWT)**
Automatic message publication on client disconnection:

```python
# Configure LWT during connection
will_message = {
    'topic': f'vehicles/{vehicle_id}/status',
    'payload': json.dumps({'status': 'offline', 'timestamp': datetime.now().isoformat()}),
    'qos': 1,
    'retain': True
}

client = MQTTClient(
    client_id=vehicle_id,
    will_message=will_message
)
```

##### **Retained Messages**
Persistent messages that new subscribers receive immediately:

```python
# Publish retained message for current status
await client.publish(
    f'vehicles/{vehicle_id}/status',
    json.dumps(current_status),
    qos=1,
    retain=True
)

# New subscribers automatically receive the retained message
```

##### **Shared Subscriptions**
Load balancing across multiple subscribers:

```python
# Shared subscription topic
shared_topic = '$share/group1/vehicles/+/telemetry'

# Multiple clients can subscribe to the same shared group
# Messages distributed among group members
await client.subscribe(shared_topic, qos=1)
```

## 6.7 RESTful API Conventions

### REST: The Web Standard for API Design

RESTful APIs provide a standardized approach to web service design, offering predictability, scalability, and ease of integration.

#### REST Principles

##### **Resource-Based Architecture**
APIs are designed around resources with consistent patterns:

```
GET    /vehicles           # List all vehicles
GET    /vehicles/{id}      # Get specific vehicle
POST   /vehicles           # Create new vehicle
PUT    /vehicles/{id}      # Update vehicle
DELETE /vehicles/{id}      # Delete vehicle

GET    /vehicles/{id}/telemetry  # Get vehicle telemetry
POST   /vehicles/{id}/commands   # Send command to vehicle
```

##### **HTTP Methods and Status Codes**
Standardized request methods and response codes:

**Methods:**
- **GET**: Retrieve resource(s) - Safe, idempotent, cacheable
- **POST**: Create new resource - Not idempotent
- **PUT**: Update existing resource - Idempotent
- **PATCH**: Partial update - Not necessarily idempotent
- **DELETE**: Remove resource - Idempotent

**Status Codes:**
- **200 OK**: Successful GET/PUT/PATCH
- **201 Created**: Successful POST (resource created)
- **204 No Content**: Successful DELETE or update with no response body
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Authentication successful but insufficient permissions
- **404 Not Found**: Resource doesn't exist
- **409 Conflict**: Request conflicts with current state
- **422 Unprocessable Entity**: Valid request but unable to process
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

#### API Design Patterns

##### **Filtering, Sorting, and Pagination**
Standard query parameters for resource collections:

```python
# Filtering
GET /vehicles?type=bus&status=active

# Sorting
GET /vehicles?sort=created_at:desc,name:asc

# Pagination
GET /vehicles?page=2&per_page=50

# Combined
GET /vehicles?type=bus&status=active&sort=name:asc&page=1&per_page=20
```

##### **Response Format Standardization**
Consistent JSON response structures:

```json
{
    "data": [
        {
            "id": "bus-001",
            "type": "electric_bus",
            "location": {"lat": 48.8566, "lng": 2.3522},
            "status": "active",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-15T10:30:00Z"
        }
    ],
    "meta": {
        "page": 1,
        "per_page": 20,
        "total": 150,
        "total_pages": 8
    },
    "links": {
        "self": "/vehicles?page=1&per_page=20",
        "next": "/vehicles?page=2&per_page=20",
        "prev": null,
        "first": "/vehicles?page=1&per_page=20",
        "last": "/vehicles?page=8&per_page=20"
    }
}
```

##### **Error Response Format**
Structured error responses for debugging:

```json
{
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "Invalid vehicle data provided",
        "details": [
            {
                "field": "license_plate",
                "message": "License plate format is invalid",
                "value": "INVALID-FORMAT"
            }
        ]
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req-12345-abcde"
}
```

## 6.8 JSON Schema and Validation

### JSON Schema: Contract-First API Design

JSON Schema provides a vocabulary for defining and validating JSON data structures, enabling robust API contracts and automatic validation.

#### Schema Definition Structure

##### **Basic Schema Components**
```json
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "id": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9_-]{1,50}$",
            "description": "Unique vehicle identifier"
        },
        "type": {
            "type": "string",
            "enum": ["bus", "car", "scooter", "truck"],
            "description": "Vehicle type classification"
        },
        "location": {
            "type": "object",
            "properties": {
                "lat": {
                    "type": "number",
                    "minimum": -90,
                    "maximum": 90,
                    "description": "Latitude in decimal degrees"
                },
                "lng": {
                    "type": "number",
                    "minimum": -180,
                    "maximum": 180,
                    "description": "Longitude in decimal degrees"
                }
            },
            "required": ["lat", "lng"]
        }
    },
    "required": ["id", "type", "location"]
}
```

##### **Advanced Validation Features**
Complex validation rules and constraints:

```json
{
    "type": "object",
    "properties": {
        "battery_level": {
            "type": "number",
            "minimum": 0,
            "maximum": 100,
            "description": "Battery charge percentage"
        },
        "charging_schedule": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "format": "date-time"},
                    "end_time": {"type": "string", "format": "date-time"},
                    "power_limit": {"type": "number", "minimum": 0, "maximum": 350}
                },
                "required": ["start_time", "end_time"]
            },
            "minItems": 1,
            "uniqueItems": false
        }
    },
    "allOf": [
        {
            "if": {"properties": {"type": {"const": "electric_bus"}}},
            "then": {
                "properties": {
                    "passenger_capacity": {"type": "integer", "minimum": 20, "maximum": 100}
                },
                "required": ["passenger_capacity"]
            }
        }
    ]
}
```

#### Schema-Driven Development

##### **Code Generation from Schemas**
Automatic generation of type-safe code:

```python
# Generated from JSON Schema
from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime

class Location(BaseModel):
    lat: float = Field(..., ge=-90, le=90, description="Latitude in decimal degrees")
    lng: float = Field(..., ge=-180, le=180, description="Longitude in decimal degrees")

class Vehicle(BaseModel):
    id: str = Field(..., regex=r'^[a-zA-Z0-9_-]{1,50}$', description="Unique vehicle identifier")
    type: str = Field(..., enum=['bus', 'car', 'scooter', 'truck'])
    location: Location
    battery_level: Optional[float] = Field(None, ge=0, le=100)
    created_at: Optional[datetime] = None

    class Config:
        schema_extra = {
            "example": {
                "id": "bus-001",
                "type": "electric_bus",
                "location": {"lat": 48.8566, "lng": 2.3522},
                "battery_level": 85.5
            }
        }
```

##### **Runtime Validation**
Automatic validation of API requests and responses:

```python
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

app = FastAPI()

@app.post("/vehicles")
async def create_vehicle(vehicle: Vehicle):
    try:
        # Vehicle is automatically validated against schema
        result = await vehicle_service.create(vehicle.dict())
        return result
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

@app.get("/vehicles/{vehicle_id}", response_model=Vehicle)
async def get_vehicle(vehicle_id: str):
    # Response is automatically validated against schema
    vehicle = await vehicle_service.get_by_id(vehicle_id)
    if not vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    return vehicle
```

This comprehensive standards implementation ensures that OpenVehicleControl can communicate effectively with any compliant vehicle or charging infrastructure, providing a truly interoperable and future-proof mobility platform.
