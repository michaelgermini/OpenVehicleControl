# 🧠 Chapter 3: Backend – API and Central Server

## 3.1 Language and Frameworks (FastAPI, Flask)

### Choosing the Right Technology Stack: Engineering Trade-offs

Selecting a technology stack for a critical infrastructure system requires careful consideration of multiple factors. Think of this as choosing materials for constructing a bridge - each material has unique properties that affect safety, cost, maintenance, and longevity.

#### The Programming Language Decision

Python was selected as the primary language for several compelling reasons:

##### **Developer Productivity and Ecosystem**
Python's extensive ecosystem provides ready-made solutions for virtually every aspect of system development:
- **Scientific computing**: NumPy, Pandas for data analysis
- **Web frameworks**: FastAPI, Flask for API development
- **Database connectivity**: SQLAlchemy, asyncpg for data persistence
- **IoT protocols**: Paho-MQTT, WebSocket libraries
- **Security**: Cryptography libraries, JWT implementations

##### **Readability and Maintainability**
The language's emphasis on readability reduces development time and improves code maintainability:
- **Clear syntax**: Code reads like pseudocode
- **Strong typing**: Type hints prevent runtime errors
- **Extensive documentation**: Rich ecosystem with comprehensive docs
- **Community standards**: PEP 8 and established best practices

##### **Performance Considerations**
While Python has a reputation for being slower than compiled languages, modern optimizations make it suitable for high-performance systems:
- **AsyncIO**: Non-blocking I/O for concurrent operations
- **JIT compilation**: PyPy for performance-critical sections
- **Native extensions**: Cython for computational bottlenecks
- **Microservices**: Horizontal scaling mitigates performance concerns

#### Framework Selection: FastAPI vs Flask

The choice between FastAPI and Flask represents a trade-off between developer experience and control:

##### **FastAPI: The Modern Async Framework**

FastAPI was chosen for its alignment with modern web development practices:

**Advantages:**
- **Automatic API documentation**: OpenAPI/Swagger generation
- **Type safety**: Pydantic models for data validation
- **Async support**: Native asynchronous request handling
- **Performance**: On par with Node.js and Go applications
- **Developer experience**: Excellent IDE support and debugging

**Architecture Benefits:**
```python
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from typing import List

app = FastAPI(title="OpenVehicleControl API")

class Vehicle(BaseModel):
    id: str
    type: str
    location: dict
    status: str

@app.get("/vehicles", response_model=List[Vehicle])
async def get_vehicles():
    # Type-safe, auto-documented endpoint
    return await vehicle_service.get_all()
```

##### **Flask: The Lightweight Alternative**

Flask serves as a fallback for specific use cases requiring maximum flexibility:

**Use Cases:**
- **Microservices**: Lightweight deployments with minimal dependencies
- **Legacy integration**: Easier migration from existing Flask applications
- **Custom protocols**: Full control over request/response handling
- **Performance optimization**: Minimal overhead for high-throughput scenarios

### Framework Architecture Patterns

#### Layered Architecture Implementation

The backend follows a clean architecture pattern separating concerns:

##### **Presentation Layer (API Routes)**
- **Request handling**: HTTP request parsing and validation
- **Response formatting**: JSON serialization and error handling
- **Authentication**: JWT token validation and user context
- **Rate limiting**: API usage control and abuse prevention

##### **Business Logic Layer (Services)**
- **Domain logic**: Core business rules and workflows
- **Data transformation**: Converting between API and internal models
- **Validation**: Business rule enforcement
- **Orchestration**: Coordinating multiple operations

##### **Data Access Layer (Repositories)**
- **Database operations**: CRUD operations with optimization
- **Query building**: Complex query construction
- **Connection management**: Pooling and transaction handling
- **Caching**: Performance optimization for frequent queries

##### **Infrastructure Layer**
- **External services**: MQTT brokers, email services
- **Monitoring**: Logging, metrics collection
- **Configuration**: Environment-specific settings
- **Security**: Encryption, key management

## 3.2 Code Structure and Monorepo Organization

### Monorepo Strategy: Unified Development Experience

The monorepo approach consolidates all related code into a single repository, providing several advantages for complex systems like OpenVehicleControl.

#### Benefits of Monorepo Organization

##### **Atomic Changes**
Large-scale refactoring can be performed atomically across all components:
```bash
# Single commit updates API, agent, and frontend together
git commit -m "Implement unified authentication system"
```

##### **Shared Code and Libraries**
Common utilities and models are easily shared:
```
shared/
├── models/          # Pydantic models used across services
├── utils/           # Common utilities and helpers
├── types/           # TypeScript/Flow type definitions
└── constants/       # Shared constants and enums
```

##### **Consistent Tooling**
Development tools and configurations remain synchronized:
- **Testing frameworks**: Same test structure across components
- **Linting rules**: Consistent code quality standards
- **Build processes**: Unified CI/CD pipelines
- **Dependency management**: Single source of truth for versions

#### Repository Structure

The monorepo follows a clear organizational hierarchy:

```
openvehiclecontrol/
├── backend/                 # FastAPI backend application
│   ├── app/
│   │   ├── api/            # API route handlers
│   │   ├── core/           # Core functionality
│   │   ├── models/         # Database models
│   │   └── services/       # Business logic
│   ├── tests/              # Backend tests
│   └── requirements.txt
├── frontend/               # React frontend application
│   ├── src/
│   ├── public/
│   └── package.json
├── agent/                  # IoT edge agent
│   ├── src/
│   └── requirements.txt
├── docs/                   # Documentation
├── docker/                 # Docker configurations
├── scripts/                # Development scripts
└── docker-compose.yml
```

### Modular Service Organization

#### API Module Structure

The backend API is organized into focused modules:

##### **Vehicle Management Module**
```python
# backend/app/api/vehicles.py
from fastapi import APIRouter, Depends
from ..services.vehicle_service import VehicleService

router = APIRouter(prefix="/vehicles")

@router.get("/")
async def list_vehicles(service: VehicleService = Depends()):
    return await service.get_all()

@router.post("/{vehicle_id}/command")
async def send_command(vehicle_id: str, command: Command):
    return await service.send_command(vehicle_id, command)
```

##### **Telemetry Module**
Handles real-time and historical data operations:
- **Ingestion endpoints**: Receiving data from IoT agents
- **Query interfaces**: Historical data retrieval
- **Aggregation APIs**: Statistical computations
- **Export functions**: Data export in various formats

##### **User Management Module**
Authentication and authorization services:
- **User registration**: Account creation and validation
- **Session management**: JWT token handling
- **Role assignment**: Permission management
- **Audit logging**: Security event tracking

## 3.3 Database (PostgreSQL + InfluxDB)

### Database Selection: Optimizing for Different Data Patterns

Different types of data require different storage characteristics. This is analogous to choosing between a filing cabinet for structured documents and a time capsule for historical artifacts.

#### PostgreSQL: The Relational Foundation

PostgreSQL serves as the primary database for structured data:

##### **Strengths for Vehicle Control Systems**
- **ACID compliance**: Ensures data consistency for critical operations
- **Complex relationships**: Handles vehicle-fleet-user associations
- **JSON support**: Stores flexible configuration data
- **Geospatial capabilities**: Location-based queries and operations
- **Extensibility**: Custom functions and data types

##### **Core Data Models**

**Vehicle Table:**
```sql
CREATE TABLE vehicles (
    id UUID PRIMARY KEY,
    external_id VARCHAR(50) UNIQUE,
    type VARCHAR(20) NOT NULL,
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    fleet_id UUID REFERENCES fleets(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

**Telemetry Configuration:**
```sql
CREATE TABLE telemetry_configs (
    vehicle_id UUID REFERENCES vehicles(id),
    sensor_type VARCHAR(50),
    sampling_rate INTEGER,
    enabled BOOLEAN DEFAULT true,
    config JSONB,  -- Flexible configuration storage
    PRIMARY KEY (vehicle_id, sensor_type)
);
```

#### InfluxDB: Time-Series Optimization

InfluxDB handles the high-volume, time-series nature of telemetry data:

##### **Time-Series Data Characteristics**
- **High ingestion rates**: Thousands of data points per second
- **Temporal queries**: Time-based aggregations and filtering
- **Data retention policies**: Automatic data aging
- **Downsampling**: Reducing granularity over time
- **Continuous queries**: Automated data processing

##### **Schema Design for Telemetry**

**Measurement Structure:**
```
vehicle_telemetry
├── tags:
│   ├── vehicle_id (string)
│   ├── sensor_type (string)
│   └── fleet_id (string)
└── fields:
    ├── value (float)
    ├── quality (integer)
    └── metadata (string)
```

**Retention Policies:**
```sql
-- High-resolution data for recent operations
CREATE RETENTION POLICY "recent" ON "vehicle_data"
DURATION 30d REPLICATION 1

-- Aggregated data for historical analysis
CREATE RETENTION POLICY "historical" ON "vehicle_data"
DURATION 1y REPLICATION 1
```

### Database Integration Patterns

#### Connection Pooling and Management

Efficient database connections prevent performance bottlenecks:

```python
# backend/app/core/database.py
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# PostgreSQL connection
engine = create_async_engine(
    "postgresql+asyncpg://user:pass@localhost/ovc",
    pool_size=20,
    max_overflow=30
)

AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession)
```

#### Data Access Patterns

##### **Repository Pattern Implementation**
```python
# backend/app/repositories/vehicle_repository.py
class VehicleRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, vehicle_id: str) -> Vehicle:
        result = await self.session.execute(
            select(Vehicle).where(Vehicle.id == vehicle_id)
        )
        return result.scalar_one_or_none()

    async def create(self, vehicle_data: dict) -> Vehicle:
        vehicle = Vehicle(**vehicle_data)
        self.session.add(vehicle)
        await self.session.commit()
        return vehicle
```

##### **Unit of Work Pattern**
Ensures atomic operations across multiple repositories:
```python
class UnitOfWork:
    def __init__(self):
        self.session = AsyncSessionLocal()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            await self.session.rollback()
        else:
            await self.session.commit()
        await self.session.close()
```

## 3.4 Data Models

### Data Modeling Philosophy: Balancing Flexibility and Structure

Effective data modeling requires balancing competing requirements: strict structure for reliability versus flexibility for adaptability.

#### Core Entity Relationships

The system models four primary entity types:

##### **Vehicles: The Physical Assets**
- **Identity**: Unique identifiers across the system
- **Classification**: Type, manufacturer, model information
- **Configuration**: Hardware and software capabilities
- **Status**: Operational state and health indicators

##### **Fleets: Organizational Grouping**
- **Hierarchy**: Nested organizational structures
- **Policies**: Default configurations and permissions
- **Boundaries**: Geographic or operational constraints
- **Metrics**: Aggregate performance indicators

##### **Users and Roles: Access Control**
- **Authentication**: Identity verification methods
- **Authorization**: Permission sets and role assignments
- **Audit**: Action tracking and accountability
- **Preferences**: Personalization settings

##### **Telemetry and Events: Time-Series Data**
- **Measurements**: Sensor readings and computed values
- **Events**: Discrete occurrences and state changes
- **Commands**: Issued instructions and responses
- **Logs**: System and application messages

### Advanced Data Patterns

#### Polymorphic Vehicle Types

Vehicles exhibit different characteristics based on type:
```python
from typing import Union
from pydantic import BaseModel

class BaseVehicle(BaseModel):
    id: str
    type: str
    location: dict

class ElectricBus(BaseVehicle):
    battery_capacity: float
    passenger_capacity: int
    route_id: str

class DeliveryVan(BaseVehicle):
    cargo_volume: float
    refrigerated: bool
    delivery_zones: list

Vehicle = Union[ElectricBus, DeliveryVan, ...]
```

#### Flexible Configuration Storage

JSON fields accommodate varying requirements:
```sql
CREATE TABLE vehicle_configs (
    vehicle_id UUID REFERENCES vehicles(id),
    config_type VARCHAR(50),
    config_data JSONB,
    version INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
```

This structure supports:
- **Type-specific settings**: Different parameters for different vehicle types
- **Version control**: Configuration history and rollback
- **Validation**: Schema enforcement for configuration data
- **Extensibility**: New configuration types without schema changes

#### Temporal Data Management

Time-series data requires specialized handling:
- **Retention policies**: Automatic data aging
- **Downsampling**: Reducing storage requirements over time
- **Compression**: Efficient storage of historical data
- **Indexing**: Optimized queries for time ranges

### Data Validation and Integrity

#### Schema Enforcement

Pydantic models ensure data integrity at the application layer:
```python
from pydantic import BaseModel, validator
from typing import Optional

class VehicleCreate(BaseModel):
    external_id: str
    type: str
    manufacturer: Optional[str]

    @validator('type')
    def validate_vehicle_type(cls, v):
        allowed_types = {'bus', 'car', 'scooter', 'truck'}
        if v not in allowed_types:
            raise ValueError(f'Vehicle type must be one of {allowed_types}')
        return v
```

#### Database Constraints

SQL constraints prevent invalid data at the database level:
```sql
ALTER TABLE vehicles
ADD CONSTRAINT check_vehicle_type
CHECK (type IN ('bus', 'car', 'scooter', 'truck'));

ALTER TABLE telemetry_configs
ADD CONSTRAINT positive_sampling_rate
CHECK (sampling_rate > 0);
```

This layered approach ensures data integrity from API input through database storage, providing both flexibility for future extensions and reliability for current operations.
