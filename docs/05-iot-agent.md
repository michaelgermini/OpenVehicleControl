# 🔌 Chapter 5: Embedded Agent (IoT Vehicle Agent)

## 5.1 Objective and Role on the Vehicle

### The IoT Agent: Digital Nervous System of the Vehicle

Imagine the IoT agent as the vehicle's digital nervous system - a sophisticated interface that transforms mechanical operations into digital intelligence. Just as the human nervous system coordinates sensory input, motor control, and cognitive processing, the IoT agent bridges the physical vehicle with the digital control infrastructure.

#### Core Mission: Sensor-to-Cloud Intelligence

The IoT agent serves three fundamental purposes:

##### **1. Data Collection and Translation**
Acting as a universal translator between diverse vehicle systems and standardized digital protocols:

- **CAN bus interpreter**: Converting proprietary vehicle messages into structured data
- **Sensor aggregator**: Collecting data from temperature, pressure, and motion sensors
- **Protocol normalizer**: Transforming various interfaces into consistent MQTT messages
- **Data enricher**: Adding contextual information like timestamps and quality metrics

##### **2. Command Execution and Safety**
Serving as a secure gateway for remote control while maintaining vehicle safety:

- **Command validator**: Ensuring received commands are safe and appropriate
- **Execution coordinator**: Sequencing operations to prevent conflicts
- **Safety monitor**: Maintaining emergency stop capabilities
- **Feedback provider**: Reporting command execution status and results

##### **3. Autonomous Edge Processing**
Providing local intelligence for real-time decision making:

- **Anomaly detector**: Identifying unusual vehicle behavior patterns
- **Local automation**: Executing predefined responses to common scenarios
- **Data filtering**: Reducing bandwidth by processing data locally
- **Offline operation**: Maintaining basic functionality during connectivity loss

### Architectural Position: Edge Intelligence Layer

The IoT agent occupies a critical position in the system hierarchy:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Vehicle       │◄──►│  IoT Agent       │◄──►│   Cloud Platform │
│   Systems       │    │  (Edge Device)   │    │   (Central Hub)  │
│   (CAN, OBD)    │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
    Physical World          Digital Translation      Digital Control
```

This positioning enables the agent to:
- **Bridge protocols**: CAN ↔ MQTT, OBD-II ↔ REST
- **Filter and compress**: Raw data → Optimized transmission
- **Execute locally**: Immediate responses without cloud round-trip
- **Cache intelligently**: Store critical data for offline operation

## 5.2 CAN, OBD-II, UART, BLE Connections

### Hardware Interface Ecosystem: Universal Vehicle Connectivity

The IoT agent must communicate with diverse vehicle systems, each using different physical and logical interfaces. This requires a comprehensive connectivity strategy that can adapt to various vehicle architectures.

#### CAN Bus Integration: The Vehicle Nervous System

##### **CAN Protocol Fundamentals**
Controller Area Network (CAN) serves as the primary communication backbone in modern vehicles:

**Electrical Characteristics:**
- **Differential signaling**: Twisted pair with 120Ω termination
- **Voltage levels**: Dominant (0V) and recessive (5V) states
- **Bit timing**: Configurable baud rates (typically 500kbps)
- **Message format**: 11-bit or 29-bit identifiers with up to 8 data bytes

##### **CAN Interface Implementation**
```python
# agent/hardware/can_interface.py
import can
import asyncio

class CANInterface:
    def __init__(self, channel='can0', bitrate=500000):
        self.bus = can.interface.Bus(
            channel=channel,
            interface='socketcan',
            bitrate=bitrate
        )
        self.filters = []
        self.listeners = []

    async def initialize(self):
        """Setup CAN bus with error handling"""
        try:
            # Test bus connectivity
            self.bus.send(can.Message(arbitration_id=0x123, data=[0x01, 0x02]))
            logger.info("CAN bus initialized successfully")
        except can.CanError as e:
            logger.error(f"CAN bus initialization failed: {e}")
            raise

    async def send_message(self, arbitration_id: int, data: bytes):
        """Send CAN message with retry logic"""
        message = can.Message(arbitration_id=arbitration_id, data=data)
        for attempt in range(3):
            try:
                self.bus.send(message)
                return True
            except can.CanError:
                if attempt == 2:
                    logger.error(f"Failed to send CAN message after 3 attempts")
                    return False
                await asyncio.sleep(0.1)

    async def receive_messages(self):
        """Continuous message reception with filtering"""
        async for message in self.bus:
            if self._passes_filters(message):
                await self._process_message(message)
```

##### **CAN Message Processing**
The agent must interpret various CAN message types:

```python
# Message type identification and processing
CAN_MESSAGE_TYPES = {
    0x100: 'engine_speed',
    0x200: 'vehicle_speed',
    0x300: 'battery_voltage',
    0x400: 'temperature_data'
}

async def _process_message(self, message: can.Message):
    """Process incoming CAN messages"""
    message_type = CAN_MESSAGE_TYPES.get(message.arbitration_id)

    if message_type == 'engine_speed':
        rpm = int.from_bytes(message.data[0:2], 'big')
        await self._publish_telemetry('engine_rpm', rpm)

    elif message_type == 'battery_voltage':
        voltage = int.from_bytes(message.data[0:2], 'big') / 100.0
        await self._publish_telemetry('battery_voltage', voltage)

    # Additional message processing...
```

#### OBD-II Integration: Standardized Diagnostics

##### **OBD-II Protocol Stack**
On-Board Diagnostics II provides standardized access to vehicle systems:

**Physical Layer:**
- **Connector**: 16-pin DLC (Data Link Connector)
- **Pin assignments**: Specific pins for power, ground, and communication
- **Voltage levels**: 12V system with K-line or CAN-based communication

**Application Layer:**
- **PID system**: Parameter IDs for standardized data requests
- **DTC codes**: Diagnostic Trouble Codes for fault diagnosis
- **Mode commands**: Different operation modes (current data, freeze frame, etc.)

##### **OBD-II Interface Implementation**
```python
# agent/hardware/obd_interface.py
import obd

class OBDInterface:
    def __init__(self, port='/dev/ttyUSB0'):
        self.connection = obd.OBD(port)
        self.supported_commands = []

    async def initialize(self):
        """Establish OBD-II connection and enumerate capabilities"""
        if not self.connection.is_connected():
            raise ConnectionError("Failed to connect to OBD-II interface")

        # Query supported PIDs
        self.supported_commands = await self._query_supported_pids()

        # Test critical commands
        if not await self._test_critical_commands():
            logger.warning("Some OBD-II commands may not be supported")

    async def read_parameter(self, pid: str) -> float:
        """Read OBD-II parameter with error handling"""
        command = obd.commands[pid]

        if command not in self.supported_commands:
            raise ValueError(f"PID {pid} not supported by vehicle")

        response = self.connection.query(command)

        if response.is_null():
            raise RuntimeError(f"Failed to read PID {pid}")

        return response.value.magnitude

    async def get_dtc_codes(self) -> list:
        """Retrieve diagnostic trouble codes"""
        response = self.connection.query(obd.commands.GET_DTC)

        if response.is_null():
            return []

        return [str(code) for code in response.value]
```

#### UART/Serial Communication: Legacy System Integration

##### **UART Protocol Handling**
Many vehicle components use simple serial communication:

```python
# agent/hardware/uart_interface.py
import serial
import asyncio

class UARTInterface:
    def __init__(self, port='/dev/ttyS0', baudrate=9600):
        self.serial = serial.Serial(
            port=port,
            baudrate=baudrate,
            timeout=1,
            parity=serial.PARITY_NONE
        )
        self.protocol_handlers = {}

    async def initialize(self):
        """Setup UART communication"""
        if not self.serial.is_open:
            self.serial.open()

        # Send initialization sequence
        await self._send_initialization()

    async def register_handler(self, message_type: str, handler):
        """Register protocol-specific message handlers"""
        self.protocol_handlers[message_type] = handler

    async def send_command(self, command: bytes):
        """Send command with acknowledgment"""
        self.serial.write(command)

        # Wait for acknowledgment
        response = await self._read_response(timeout=2.0)

        if not self._is_acknowledgment(response):
            raise CommunicationError("Command not acknowledged")

    async def listen_for_messages(self):
        """Continuous message reception"""
        while True:
            try:
                message = await self._read_message()
                await self._dispatch_message(message)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"UART message processing error: {e}")
```

#### Bluetooth Low Energy (BLE): Wireless Sensor Networks

##### **BLE Integration for Modern Sensors**
BLE enables wireless connectivity with modern vehicle sensors:

```python
# agent/hardware/ble_interface.py
from bleak import BleakClient, BleakScanner
import asyncio

class BLEInterface:
    def __init__(self):
        self.connected_devices = {}
        self.scanner = BleakScanner()

    async def scan_for_devices(self, service_uuid: str) -> list:
        """Scan for BLE devices with specific service"""
        devices = await self.scanner.discover()

        matching_devices = []
        for device in devices:
            if service_uuid in device.metadata.get('uuids', []):
                matching_devices.append(device)

        return matching_devices

    async def connect_to_sensor(self, device_address: str):
        """Connect to BLE sensor device"""
        client = BleakClient(device_address)

        try:
            await client.connect()
            self.connected_devices[device_address] = client

            # Setup notification handlers
            await self._setup_notifications(client)

            logger.info(f"Connected to BLE device: {device_address}")

        except Exception as e:
            logger.error(f"BLE connection failed: {e}")
            raise

    async def read_sensor_data(self, device_address: str, characteristic_uuid: str):
        """Read data from BLE characteristic"""
        client = self.connected_devices.get(device_address)

        if not client or not client.is_connected:
            raise ConnectionError("BLE device not connected")

        data = await client.read_gatt_char(characteristic_uuid)
        return self._parse_sensor_data(data)
```

## 5.3 Supported Protocols

### Protocol Ecosystem: Standards Compliance and Interoperability

The IoT agent must support multiple protocols to ensure broad vehicle compatibility while maintaining standardized communication with the cloud platform.

#### SAE J1979 / OBD-II: Diagnostic Standard

##### **Protocol Implementation**
Complete OBD-II protocol stack with all standardized PIDs:

```python
# Comprehensive OBD-II PID definitions
OBD_PIDS = {
    # Powertrain
    'ENGINE_RPM': {'pid': 0x0C, 'bytes': 2, 'formula': lambda x: x / 4},
    'VEHICLE_SPEED': {'pid': 0x0D, 'bytes': 1, 'formula': lambda x: x},
    'COOLANT_TEMP': {'pid': 0x05, 'bytes': 1, 'formula': lambda x: x - 40},

    # Battery/Electric
    'BATTERY_VOLTAGE': {'pid': 0x42, 'bytes': 2, 'formula': lambda x: x / 1000},
    'BATTERY_CURRENT': {'pid': 0x43, 'bytes': 2, 'formula': lambda x: (x - 32768) / 100},

    # Additional sensors...
}

class OBDProtocolHandler:
    def __init__(self, obd_interface):
        self.interface = obd_interface
        self.pid_cache = {}

    async def read_all_supported_pids(self) -> dict:
        """Read all supported PIDs efficiently"""
        results = {}

        for pid_name, config in OBD_PIDS.items():
            try:
                raw_value = await self.interface.read_parameter(config['pid'])
                processed_value = config['formula'](raw_value)
                results[pid_name] = {
                    'value': processed_value,
                    'timestamp': datetime.now(),
                    'quality': 'good'
                }
            except Exception as e:
                logger.warning(f"Failed to read PID {pid_name}: {e}")
                results[pid_name] = {
                    'error': str(e),
                    'timestamp': datetime.now(),
                    'quality': 'error'
                }

        return results
```

#### UDS (ISO 14229): Unified Diagnostic Services

##### **Advanced Diagnostic Capabilities**
UDS provides sophisticated diagnostic and reprogramming capabilities:

```python
# UDS service implementations
UDS_SERVICES = {
    'DIAGNOSTIC_SESSION_CONTROL': 0x10,
    'ECU_RESET': 0x11,
    'SECURITY_ACCESS': 0x27,
    'COMMUNICATION_CONTROL': 0x28,
    'TESTER_PRESENT': 0x3E,
    'READ_DATA_BY_IDENTIFIER': 0x22,
    'WRITE_DATA_BY_IDENTIFIER': 0x2E,
    'ROUTINE_CONTROL': 0x31
}

class UDSProtocolHandler:
    def __init__(self, can_interface):
        self.can = can_interface
        self.session_active = False
        self.security_unlocked = False

    async def establish_session(self, session_type: int = 0x01):
        """Establish diagnostic session"""
        request = [UDS_SERVICES['DIAGNOSTIC_SESSION_CONTROL'], session_type]
        response = await self._send_uds_request(request)

        if response[0] == 0x50:  # Positive response
            self.session_active = True
            return True

        return False

    async def read_did(self, identifier: int) -> bytes:
        """Read Data Identifier"""
        request = [
            UDS_SERVICES['READ_DATA_BY_IDENTIFIER'],
            (identifier >> 8) & 0xFF,
            identifier & 0xFF
        ]

        response = await self._send_uds_request(request)

        if response[0] == 0x62:  # Positive response
            return response[3:]  # Return data bytes

        raise UDSException(f"Failed to read DID {identifier:04X}")

    async def security_access(self, seed_function, key_function):
        """Perform security unlock sequence"""
        # Request seed
        seed_request = [UDS_SERVICES['SECURITY_ACCESS'], 0x01]
        seed_response = await self._send_uds_request(seed_request)

        if seed_response[0] != 0x67:
            raise UDSException("Security access seed request failed")

        seed = seed_response[2:6]  # Extract seed bytes

        # Calculate key
        key = key_function(seed)

        # Send key
        key_request = [UDS_SERVICES['SECURITY_ACCESS'], 0x02] + list(key)
        key_response = await self._send_uds_request(key_request)

        if key_response[0] == 0x67 and key_response[1] == 0x02:
            self.security_unlocked = True
            return True

        return False
```

#### ISO 15118: EV Plug & Charge

##### **Electric Vehicle Charging Communication**
Implementation of the ISO 15118 standard for automated charging:

```python
# ISO 15118 message types
ISO15118_MESSAGES = {
    'SESSION_SETUP_REQ': 0x01,
    'SESSION_SETUP_RES': 0x02,
    'SERVICE_DISCOVERY_REQ': 0x03,
    'SERVICE_DISCOVERY_RES': 0x04,
    'PAYMENT_SERVICE_SELECTION_REQ': 0x05,
    'PAYMENT_SERVICE_SELECTION_RES': 0x06,
    'AUTHORIZATION_REQ': 0x07,
    'AUTHORIZATION_RES': 0x08,
    'CHARGE_PARAMETER_DISCOVERY_REQ': 0x09,
    'CHARGE_PARAMETER_DISCOVERY_RES': 0x0A
}

class ISO15118Handler:
    def __init__(self, can_interface):
        self.can = can_interface
        self.session_id = None
        self.contract_id = None

    async def initiate_plug_and_charge(self, evcc_id: str) -> dict:
        """Complete Plug & Charge handshake"""
        # Session Setup
        session_response = await self._session_setup(evcc_id)
        self.session_id = session_response['session_id']

        # Service Discovery
        services = await self._service_discovery()

        # Payment Service Selection
        payment_response = await self._select_payment_service(services)

        # Authorization
        auth_response = await self._authorize_payment()

        # Charge Parameter Discovery
        charge_params = await self._discover_charge_parameters()

        return {
            'session_id': self.session_id,
            'contract_id': self.contract_id,
            'charge_parameters': charge_params,
            'status': 'ready_to_charge'
        }

    async def _session_setup(self, evcc_id: str):
        """Establish charging session"""
        message = ISO15118Message(
            type=ISO15118_MESSAGES['SESSION_SETUP_REQ'],
            evcc_id=evcc_id
        )

        response = await self.can.send_and_receive(message)

        if response.type != ISO15118_MESSAGES['SESSION_SETUP_RES']:
            raise ISO15118Exception("Session setup failed")

        return {
            'session_id': response.session_id,
            'secc_version': response.version
        }
```

#### OCPP (Open Charge Point Protocol)

##### **Charging Station Communication**
OCPP integration for charging infrastructure management:

```python
# OCPP message types
OCPP_OPERATIONS = {
    'BOOT_NOTIFICATION': 'BootNotification',
    'STATUS_NOTIFICATION': 'StatusNotification',
    'AUTHORIZE': 'Authorize',
    'START_TRANSACTION': 'StartTransaction',
    'STOP_TRANSACTION': 'StopTransaction',
    'METER_VALUES': 'MeterValues'
}

class OCPPHandler:
    def __init__(self, websocket_url: str, charge_point_id: str):
        self.ws_url = websocket_url
        self.cp_id = charge_point_id
        self.connection = None
        self.transaction_id = None

    async def connect(self):
        """Establish OCPP connection"""
        self.connection = await websockets.connect(
            f"{self.ws_url}/{self.cp_id}",
            subprotocols=['ocpp1.6']
        )

        # Send boot notification
        await self._send_boot_notification()

        # Start message handling loop
        asyncio.create_task(self._message_handler())

    async def start_charging(self, connector_id: int, id_tag: str) -> dict:
        """Initiate charging session"""
        request = {
            'connectorId': connector_id,
            'idTag': id_tag,
            'timestamp': datetime.now().isoformat(),
            'meterStart': await self._get_meter_value(connector_id)
        }

        response = await self._call_operation('StartTransaction', request)

        if response['idTagInfo']['status'] == 'Accepted':
            self.transaction_id = response['transactionId']
            return {
                'transaction_id': self.transaction_id,
                'status': 'charging'
            }

        raise OCPPException(f"Transaction rejected: {response['idTagInfo']['status']}")

    async def send_meter_values(self, connector_id: int, values: list):
        """Send meter readings"""
        request = {
            'connectorId': connector_id,
            'transactionId': self.transaction_id,
            'meterValue': values
        }

        await self._call_operation('MeterValues', request)
```

## 5.4 Data Collection and Publishing via MQTT

### MQTT Integration: Efficient IoT Data Transport

MQTT serves as the primary protocol for publishing telemetry data to the cloud platform, offering reliability, efficiency, and scalability.

#### MQTT Client Architecture

##### **Connection Management**
Robust connection handling with automatic reconnection:

```python
# agent/mqtt/client.py
import paho.mqtt.client as mqtt
import asyncio
import json

class MQTTClient:
    def __init__(self, broker_url: str, client_id: str, tls_config: dict = None):
        self.broker_url = broker_url
        self.client_id = client_id
        self.client = mqtt.Client(client_id=client_id, clean_session=False)
        self.tls_config = tls_config

        # Setup callbacks
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_publish = self._on_publish

        # QoS settings
        self.default_qos = 1  # At least once delivery

    async def connect(self):
        """Establish MQTT connection with TLS"""
        if self.tls_config:
            self.client.tls_set(**self.tls_config)

        # Connect with keepalive
        self.client.connect(self.broker_url, keepalive=60)

        # Start network loop in background
        self.client.loop_start()

        # Wait for connection
        await self._wait_for_connection()

    async def publish_telemetry(self, topic: str, payload: dict, qos: int = None):
        """Publish telemetry data with error handling"""
        if qos is None:
            qos = self.default_qos

        # Serialize payload
        message = json.dumps(payload)

        # Publish with retry logic
        result = self.client.publish(topic, message, qos=qos)

        # Wait for publish confirmation
        result.wait_for_publish(timeout=5.0)

        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise MQTTPublishError(f"Failed to publish: {result.rc}")

    def _on_connect(self, client, userdata, flags, rc):
        """Handle connection established"""
        if rc == 0:
            logger.info("MQTT connected successfully")
            self.connected_event.set()
        else:
            logger.error(f"MQTT connection failed: {rc}")

    def _on_disconnect(self, client, userdata, rc):
        """Handle disconnection"""
        logger.warning(f"MQTT disconnected: {rc}")
        self.connected_event.clear()

        # Trigger reconnection if unexpected
        if rc != 0:
            asyncio.create_task(self._reconnect())
```

#### Topic Structure and Naming Convention

##### **Hierarchical Topic Design**
Well-structured topics enable efficient routing and filtering:

```python
# Topic hierarchy definition
TOPIC_HIERARCHY = {
    'telemetry': 'vehicles/{vehicle_id}/telemetry/{sensor_type}',
    'status': 'vehicles/{vehicle_id}/status',
    'commands': 'vehicles/{vehicle_id}/commands',
    'events': 'vehicles/{vehicle_id}/events/{event_type}',
    'diagnostics': 'vehicles/{vehicle_id}/diagnostics/{component}'
}

class TopicManager:
    @staticmethod
    def get_telemetry_topic(vehicle_id: str, sensor_type: str) -> str:
        """Generate telemetry topic"""
        return f"vehicles/{vehicle_id}/telemetry/{sensor_type}"

    @staticmethod
    def get_status_topic(vehicle_id: str) -> str:
        """Generate status topic"""
        return f"vehicles/{vehicle_id}/status"

    @staticmethod
    def get_command_topic(vehicle_id: str) -> str:
        """Generate command topic"""
        return f"vehicles/{vehicle_id}/commands"
```

#### Data Publishing Strategy

##### **Efficient Data Batching and Compression**
Optimizing bandwidth usage for resource-constrained environments:

```python
# agent/data/publisher.py
class DataPublisher:
    def __init__(self, mqtt_client, vehicle_id: str):
        self.mqtt = mqtt_client
        self.vehicle_id = vehicle_id
        self.batch_size = 10
        self.batch_interval = 30  # seconds
        self.data_buffer = defaultdict(list)

    async def start_publishing(self):
        """Start periodic data publishing"""
        while True:
            await asyncio.sleep(self.batch_interval)
            await self._publish_batch()

    async def add_telemetry_data(self, sensor_type: str, data: dict):
        """Add data to publishing buffer"""
        self.data_buffer[sensor_type].append({
            'timestamp': datetime.now().isoformat(),
            'data': data
        })

        # Publish immediately if batch size reached
        if len(self.data_buffer[sensor_type]) >= self.batch_size:
            await self._publish_sensor_data(sensor_type)

    async def _publish_sensor_data(self, sensor_type: str):
        """Publish buffered sensor data"""
        if not self.data_buffer[sensor_type]:
            return

        # Compress data if beneficial
        data_batch = self.data_buffer[sensor_type]
        if len(data_batch) > 1:
            payload = self._compress_batch(data_batch)
        else:
            payload = data_batch[0]

        topic = TopicManager.get_telemetry_topic(self.vehicle_id, sensor_type)

        try:
            await self.mqtt.publish_telemetry(topic, payload)
            self.data_buffer[sensor_type].clear()
        except Exception as e:
            logger.error(f"Failed to publish {sensor_type} data: {e}")

    def _compress_batch(self, data_batch: list) -> dict:
        """Compress multiple readings into efficient format"""
        return {
            'batch': True,
            'count': len(data_batch),
            'start_time': data_batch[0]['timestamp'],
            'end_time': data_batch[-1]['timestamp'],
            'data_points': [point['data'] for point in data_batch],
            'compression': 'delta_encoding'  # Could implement actual compression
        }
```

## 5.5 Downstream Commands and Digital Signatures

### Secure Command Execution: Digital Signatures and Validation

Commands sent to vehicles carry significant safety implications, requiring cryptographic verification to prevent unauthorized or malicious operations.

#### Command Reception and Validation

##### **MQTT Command Subscription**
Listening for incoming commands with proper authentication:

```python
# agent/commands/receiver.py
class CommandReceiver:
    def __init__(self, mqtt_client, vehicle_id: str, crypto_verifier):
        self.mqtt = mqtt_client
        self.vehicle_id = vehicle_id
        self.crypto = crypto_verifier
        self.command_handlers = {}

    async def start_listening(self):
        """Subscribe to command topics"""
        command_topic = TopicManager.get_command_topic(self.vehicle_id)
        await self.mqtt.subscribe(command_topic)

        # Setup message handler
        self.mqtt.on_message = self._handle_command_message

    async def _handle_command_message(self, message):
        """Process incoming command messages"""
        try:
            command_payload = json.loads(message.payload)

            # Verify command signature
            if not await self._verify_command_signature(command_payload):
                logger.warning("Command signature verification failed")
                return

            # Validate command safety
            if not await self._validate_command_safety(command_payload):
                logger.warning("Command safety validation failed")
                return

            # Execute command
            await self._execute_command(command_payload)

        except Exception as e:
            logger.error(f"Command processing error: {e}")

    async def _verify_command_signature(self, command: dict) -> bool:
        """Verify cryptographic signature of command"""
        signature = command.get('signature')
        signed_data = command.get('signed_data')

        if not signature or not signed_data:
            return False

        # Verify against trusted public keys
        return await self.crypto.verify_signature(signed_data, signature)

    async def _validate_command_safety(self, command: dict) -> bool:
        """Validate command safety constraints"""
        command_type = command.get('type')

        # Check vehicle state compatibility
        if command_type in ['accelerate', 'brake'] and self.vehicle_state == 'maintenance':
            return False

        # Check speed limits
        if command_type == 'set_speed_limit':
            max_limit = command.get('limit', 0)
            if max_limit > self.max_safe_speed:
                return False

        # Additional safety checks...
        return True
```

#### Command Execution with Safety Guards

##### **Safe Command Execution Framework**
Executing commands with comprehensive safety monitoring:

```python
# agent/commands/executor.py
class CommandExecutor:
    def __init__(self, hardware_interfaces, safety_monitor):
        self.hardware = hardware_interfaces
        self.safety = safety_monitor
        self.active_commands = {}
        self.emergency_stop = False

    async def execute_command(self, command: dict) -> dict:
        """Execute command with safety monitoring"""
        command_id = command['id']
        command_type = command['type']

        # Check for emergency stop
        if self.emergency_stop:
            return {'status': 'rejected', 'reason': 'emergency_stop_active'}

        # Start safety monitoring
        safety_task = asyncio.create_task(
            self._monitor_command_safety(command_id)
        )

        try:
            # Execute command based on type
            if command_type == 'set_speed_limit':
                result = await self._execute_speed_limit(command)
            elif command_type == 'start_charging':
                result = await self._execute_charging(command)
            elif command_type == 'diagnostic_reset':
                result = await self._execute_diagnostic_reset(command)
            else:
                result = {'status': 'unknown_command'}

            # Stop safety monitoring
            safety_task.cancel()

            return result

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            safety_task.cancel()
            return {'status': 'failed', 'error': str(e)}

    async def _monitor_command_safety(self, command_id: str):
        """Monitor command execution for safety violations"""
        try:
            while True:
                await asyncio.sleep(0.1)  # Check every 100ms

                # Check system parameters
                if await self.safety.detect_anomaly():
                    logger.warning(f"Safety anomaly detected for command {command_id}")
                    await self._emergency_stop()
                    break

        except asyncio.CancelledError:
            pass

    async def _emergency_stop(self):
        """Execute emergency stop procedure"""
        logger.critical("Executing emergency stop")
        self.emergency_stop = True

        # Stop all active operations
        for command_id in self.active_commands:
            await self._abort_command(command_id)

        # Put vehicle in safe state
        await self.hardware.emergency_stop_all()
```

## 5.6 Embedded Security (TPM, Secure Element)

### Embedded Security: Hardware-Based Protection

Security in embedded systems requires hardware-assisted protection mechanisms to prevent tampering and ensure secure operation.

#### TPM (Trusted Platform Module) Integration

##### **TPM-Based Security Services**
Leveraging TPM for cryptographic operations and secure storage:

```python
# agent/security/tpm_manager.py
import tpm2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class TPMManager:
    def __init__(self):
        self.tpm = tpm2.TPM2()
        self.key_handle = None

    async def initialize(self):
        """Initialize TPM and load/create keys"""
        try:
            # Create or load RSA key pair in TPM
            self.key_handle = await self._load_or_create_key()

            # Initialize PCR (Platform Configuration Registers)
            await self._initialize_pcrs()

            logger.info("TPM initialized successfully")

        except Exception as e:
            logger.error(f"TPM initialization failed: {e}")
            raise

    async def sign_data(self, data: bytes) -> bytes:
        """Sign data using TPM private key"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        data_hash = digest.finalize()

        signature = await self.tpm.sign(
            key_handle=self.key_handle,
            digest=data_hash,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        )

        return signature

    async def verify_signature(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verify signature (can be done without TPM)"""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    async def _load_or_create_key(self) -> int:
        """Load existing key or create new one"""
        # Check if key already exists
        try:
            key_handle = await self.tpm.load_key(key_file="vehicle_key")
            return key_handle
        except tpm2.TPM2Error:
            pass

        # Create new RSA key pair
        key_handle = await self.tpm.create_key(
            algorithm=tpm2.Algorithm.RSA,
            key_size=2048,
            attributes=tpm2.KeyAttributes.SIGN_ENCRYPT
        )

        # Persist key for future use
        await self.tpm.persist_key(key_handle, "vehicle_key")

        return key_handle
```

#### Secure Element Integration

##### **Hardware Security Module Operations**
Using secure elements for sensitive cryptographic operations:

```python
# agent/security/secure_element.py
class SecureElement:
    def __init__(self, interface):
        self.interface = interface  # SPI, I2C, etc.
        self.session_key = None

    async def initialize(self):
        """Establish secure communication with SE"""
        # Perform mutual authentication
        challenge = os.urandom(16)
        response = await self._send_apdu(0x00, 0xA4, 0x04, 0x00, challenge)

        # Verify SE certificate
        se_cert = await self._get_certificate()
        if not await self._verify_se_certificate(se_cert):
            raise SecurityError("Secure Element authentication failed")

        # Establish session encryption
        self.session_key = await self._establish_session_key()

    async def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using SE"""
        apdu = self._build_encrypt_apdu(data)
        response = await self._send_secure_apdu(apdu)
        return response.data

    async def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using SE"""
        apdu = self._build_decrypt_apdu(encrypted_data)
        response = await self._send_secure_apdu(apdu)
        return response.data

    async def generate_signature(self, data: bytes) -> bytes:
        """Generate digital signature using SE private key"""
        digest = await self._hash_data(data)
        apdu = self._build_sign_apdu(digest)
        response = await self._send_secure_apdu(apdu)
        return response.signature

    async def _send_secure_apdu(self, apdu: bytes) -> APDUResponse:
        """Send APDU with session encryption"""
        if self.session_key:
            encrypted_apdu = await self._encrypt_apdu(apdu)
            response = await self.interface.send_apdu(encrypted_apdu)
            return await self._decrypt_response(response)
        else:
            return await self.interface.send_apdu(apdu)
```

## 5.7 OTA Updates (Over The Air)

### Over-The-Air Updates: Remote Software Maintenance

OTA updates enable remote software maintenance while ensuring update safety and reliability.

#### OTA Update Architecture

##### **Update Management System**
Coordinated update process with rollback capabilities:

```python
# agent/ota/update_manager.py
class UpdateManager:
    def __init__(self, mqtt_client, version_manager, security_manager):
        self.mqtt = mqtt_client
        self.version = version_manager
        self.security = security_manager
        self.update_in_progress = False

    async def check_for_updates(self):
        """Check for available updates"""
        current_version = await self.version.get_current_version()

        # Query update server
        available_updates = await self._query_update_server(current_version)

        for update in available_updates:
            if await self._should_install_update(update):
                await self._initiate_update(update)

    async def _initiate_update(self, update_info: dict):
        """Start update process"""
        if self.update_in_progress:
            logger.warning("Update already in progress")
            return

        self.update_in_progress = True

        try:
            # Download update package
            package = await self._download_update_package(update_info)

            # Verify package integrity and signature
            if not await self._verify_update_package(package):
                raise UpdateError("Package verification failed")

            # Check system compatibility
            if not await self._check_compatibility(package):
                raise UpdateError("Update not compatible with current system")

            # Create backup for rollback
            await self._create_backup()

            # Install update
            await self._install_update(package)

            # Verify installation
            if not await self._verify_installation(package):
                await self._rollback_update()
                raise UpdateError("Installation verification failed")

            # Clean up
            await self._cleanup_backup()

            logger.info(f"Update {update_info['version']} installed successfully")

        except Exception as e:
            logger.error(f"Update failed: {e}")
            await self._rollback_update()
        finally:
            self.update_in_progress = False

    async def _download_update_package(self, update_info: dict) -> bytes:
        """Download update package with resume capability"""
        url = update_info['download_url']
        expected_hash = update_info['sha256_hash']

        # Implement resumable download
        package_data = await self._resumable_download(url, expected_hash)

        return package_data

    async def _verify_update_package(self, package: bytes) -> bool:
        """Verify package signature and integrity"""
        # Check cryptographic signature
        signature_valid = await self.security.verify_package_signature(package)

        if not signature_valid:
            return False

        # Verify package contents (A/B update mechanism)
        return await self._verify_package_contents(package)

    async def _install_update(self, package: bytes):
        """Install update using A/B partitioning"""
        # Determine target partition
        target_partition = await self._get_update_partition()

        # Extract and install to target partition
        await self._extract_package(package, target_partition)

        # Update boot configuration
        await self._update_boot_config(target_partition)

        logger.info(f"Update installed to partition {target_partition}")

    async def _rollback_update(self):
        """Rollback to previous version"""
        logger.warning("Initiating update rollback")

        try:
            # Switch back to previous partition
            await self._switch_boot_partition()

            # Reboot to activate rollback
            await self._system_reboot()

        except Exception as e:
            logger.critical(f"Rollback failed: {e}")
            # Emergency recovery procedures...
```

#### Update Safety Mechanisms

##### **A/B Update Partitioning**
Dual partition system for safe updates:

```python
# agent/ota/partition_manager.py
class PartitionManager:
    def __init__(self):
        self.current_partition = None
        self.update_partition = None

    async def initialize(self):
        """Determine current active partition"""
        self.current_partition = await self._get_active_partition()
        self.update_partition = 'B' if self.current_partition == 'A' else 'A'

    async def get_update_partition(self) -> str:
        """Get partition for update installation"""
        return self.update_partition

    async def switch_boot_partition(self):
        """Switch active boot partition"""
        # Update U-Boot environment or similar
        await self._set_boot_partition(self.current_partition)

        # For immediate effect, some systems may need:
        # await self._mark_partition_valid(self.update_partition)

    async def _get_active_partition(self) -> str:
        """Determine which partition is currently active"""
        # Read from U-Boot environment or kernel cmdline
        with open('/proc/cmdline', 'r') as f:
            cmdline = f.read()

        if 'root=/dev/mmcblk0p2' in cmdline:
            return 'A'
        elif 'root=/dev/mmcblk0p3' in cmdline:
            return 'B'
        else:
            raise SystemError("Unable to determine active partition")
```

This comprehensive IoT agent implementation provides robust vehicle connectivity, secure command execution, and reliable data collection while maintaining the safety and reliability required for critical transportation infrastructure. The modular design enables easy adaptation to different vehicle types and communication protocols while ensuring consistent operation across the entire OpenVehicleControl ecosystem.
