# 🧰 Chapter 9: Development Tools and Deployment

## 9.1 Docker and Docker Compose

### Containerization: The Shipping Container Revolution for Software

Just as standardized shipping containers revolutionized global trade by providing consistent, reliable, and efficient transportation of goods, Docker containers have transformed software development and deployment. Understanding containerization requires recognizing it as both a technology and a methodology for creating reproducible, scalable software environments.

#### Docker Fundamentals for Vehicle Control Systems

##### **Container Architecture Principles**
The effectiveness of Docker in vehicle control systems stems from several key principles:

**Isolation and Consistency:**
```dockerfile
# Multi-stage build for IoT agent - combining build and runtime environments
FROM python:3.9-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage - minimal footprint
FROM python:3.9-slim as runtime

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libusb-1.0-0 \
    can-utils \
    && rm -rf /var/lib/apt/lists/*

# Copy built application
COPY --from=builder /root/.local /root/.local
COPY . .

# Configure Python path
ENV PATH=/root/.local/bin:$PATH

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import vehicle_agent; print('Agent healthy')" || exit 1

EXPOSE 8080
CMD ["python", "main.py"]
```

**Layer Optimization:**
```dockerfile
# Optimized layer caching for faster builds
FROM ubuntu:20.04

# Install system dependencies (changes infrequently)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files (changes moderately)
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy source code (changes frequently)
COPY . .

CMD ["python3", "app.py"]
```

#### Docker Compose for Orchestration

##### **Multi-Service Architecture Definition**
Docker Compose transforms individual containers into coordinated systems, much like an orchestra conductor brings individual musicians into harmonious performance.

```yaml
# docker-compose.yml - Complete OpenVehicleControl stack
version: '3.8'

services:
  # PostgreSQL database
  database:
    image: postgres:13
    environment:
      POSTGRES_DB: openvehiclecontrol
      POSTGRES_USER: ovc_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ovc_user -d openvehiclecontrol"]
      interval: 10s
      timeout: 5s
      retries: 5

  # InfluxDB time-series database
  influxdb:
    image: influxdb:2.0
    environment:
      DOCKER_INFLUXDB_INIT_MODE: setup
      DOCKER_INFLUXDB_INIT_USERNAME: ovc_user
      DOCKER_INFLUXDB_INIT_PASSWORD: ${INFLUX_PASSWORD}
      DOCKER_INFLUXDB_INIT_ORG: openvehiclecontrol
      DOCKER_INFLUXDB_INIT_BUCKET: telemetry
    volumes:
      - influxdb_data:/var/lib/influxdb2
      - influxdb_config:/etc/influxdb2
    networks:
      - backend
    ports:
      - "8086:8086"

  # Redis for caching and session management
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - backend
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  # FastAPI backend
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://ovc_user:${DB_PASSWORD}@database/openvehiclecontrol
      INFLUX_URL: http://influxdb:8086
      REDIS_URL: redis://redis:6379
      SECRET_KEY: ${SECRET_KEY}
    volumes:
      - ./backend:/app
    depends_on:
      database:
        condition: service_healthy
      influxdb:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - backend
      - frontend
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # React frontend
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    environment:
      REACT_APP_API_URL: http://backend:8000
    volumes:
      - ./frontend:/app
      - /app/node_modules
    depends_on:
      - backend
    networks:
      - frontend
    ports:
      - "3000:3000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3

  # IoT agent simulator for development
  agent-simulator:
    build:
      context: ./agent
      dockerfile: Dockerfile.simulator
    environment:
      BACKEND_URL: http://backend:8000
      SIMULATION_MODE: development
    depends_on:
      - backend
    networks:
      - backend
    profiles:
      - dev

  # Grafana for dashboards
  grafana:
    image: grafana/grafana:8.5.0
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD}
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    depends_on:
      - influxdb
    networks:
      - backend
      - frontend
    ports:
      - "3001:3000"

volumes:
  postgres_data:
  influxdb_data:
  influxdb_config:
  redis_data:
  grafana_data:

networks:
  backend:
    driver: bridge
  frontend:
    driver: bridge
```

#### Development Workflow with Docker

##### **Hot Reload Development Environment**
```yaml
# docker-compose.dev.yml - Development overrides
version: '3.8'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.dev
    volumes:
      - ./backend:/app
    environment:
      - DEBUG=1
      - RELOAD=1
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.dev
    volumes:
      - ./frontend:/app
      - /app/node_modules
    environment:
      - NODE_ENV=development
    command: npm start

  agent:
    build:
      context: ./agent
      dockerfile: Dockerfile.dev
    volumes:
      - ./agent:/app
    environment:
      - DEBUG=1
```

## 9.2 CI/CD (GitHub Actions)

### Continuous Integration/Continuous Deployment: The Assembly Line for Software

CI/CD represents the industrialization of software development, transforming artisanal code creation into automated, reliable, and scalable production processes. Just as Henry Ford's assembly line revolutionized automobile manufacturing, CI/CD has revolutionized software delivery.

#### GitHub Actions Workflow Architecture

##### **Complete CI/CD Pipeline**
```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # Security scanning and linting
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run security scan
        uses: github/super-linter/slim@v4
        env:
          DEFAULT_BRANCH: main
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Dependency vulnerability scan
        uses: github/codeql-action/init@v2
        with:
          languages: python, javascript

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2

  # Backend testing
  backend-test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      influxdb:
        image: influxdb:2.0
        env:
          DOCKER_INFLUXDB_INIT_MODE: setup
          DOCKER_INFLUXDB_INIT_USERNAME: test
          DOCKER_INFLUXDB_INIT_PASSWORD: test123
          DOCKER_INFLUXDB_INIT_ORG: test
          DOCKER_INFLUXDB_INIT_BUCKET: test

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt
          pip install -r requirements-dev.txt

      - name: Run linting
        run: |
          cd backend
          flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
          flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

      - name: Run tests
        run: |
          cd backend
          pytest --cov=. --cov-report=xml --cov-report=html

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./backend/coverage.xml
          flags: backend

  # Frontend testing
  frontend-test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json

      - name: Install dependencies
        run: |
          cd frontend
          npm ci

      - name: Run linting
        run: |
          cd frontend
          npm run lint

      - name: Run type checking
        run: |
          cd frontend
          npm run type-check

      - name: Run tests
        run: |
          cd frontend
          npm run test:ci

      - name: Build application
        run: |
          cd frontend
          npm run build

  # Agent testing
  agent-test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          cd agent
          pip install -r requirements.txt
          pip install -r requirements-dev.txt

      - name: Run tests
        run: |
          cd agent
          pytest --cov=. --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./agent/coverage.xml
          flags: agent

  # Integration testing
  integration-test:
    runs-on: ubuntu-latest
    needs: [backend-test, frontend-test, agent-test]
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      influxdb:
        image: influxdb:2.0
        env:
          DOCKER_INFLUXDB_INIT_MODE: setup
          DOCKER_INFLUXDB_INIT_USERNAME: test
          DOCKER_INFLUXDB_INIT_PASSWORD: test123
          DOCKER_INFLUXDB_INIT_ORG: test
          DOCKER_INFLUXDB_INIT_BUCKET: test

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Build test environment
        run: docker-compose -f docker-compose.test.yml build

      - name: Run integration tests
        run: docker-compose -f docker-compose.test.yml run --rm test

  # Build and push containers
  build-and-push:
    runs-on: ubuntu-latest
    needs: [security, backend-test, frontend-test, agent-test, integration-test]
    if: github.ref == 'refs/heads/main'

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v2
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v4
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=sha
            type=raw,value=latest,enable={{is_default_branch}}

      - name: Build and push backend
        uses: docker/build-push-action@v3
        with:
          context: ./backend
          push: true
          tags: ${{ steps.meta.outputs.tags }}-backend
          labels: ${{ steps.meta.outputs.labels }}

      - name: Build and push frontend
        uses: docker/build-push-action@v3
        with:
          context: ./frontend
          push: true
          tags: ${{ steps.meta.outputs.tags }}-frontend
          labels: ${{ steps.meta.outputs.labels }}

      - name: Build and push agent
        uses: docker/build-push-action@v3
        with:
          context: ./agent
          push: true
          tags: ${{ steps.meta.outputs.tags }}-agent
          labels: ${{ steps.meta.outputs.labels }}

  # Deploy to staging
  deploy-staging:
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/main'
    environment: staging

    steps:
      - name: Deploy to staging
        run: |
          echo "Deploying to staging environment"
          # Add deployment commands here

  # Deploy to production
  deploy-production:
    runs-on: ubuntu-latest
    needs: deploy-staging
    if: github.ref == 'refs/heads/main'
    environment: production

    steps:
      - name: Deploy to production
        run: |
          echo "Deploying to production environment"
          # Add deployment commands here
```

#### Advanced CI/CD Patterns

##### **Matrix Testing for Multiple Environments**
```yaml
# Matrix testing for different Python versions and databases
test-matrix:
  runs-on: ubuntu-latest
  strategy:
    matrix:
      python-version: ['3.8', '3.9', '3.10']
      database: ['postgres', 'mysql']
      exclude:
        - python-version: '3.8'
          database: 'mysql'

  steps:
    - name: Setup Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Setup database
      if: matrix.database == 'postgres'
      run: |
        sudo systemctl start postgresql
        createdb test_db

    - name: Setup database
      if: matrix.database == 'mysql'
      run: |
        sudo systemctl start mysql
        mysql -e 'CREATE DATABASE test_db;'

    - name: Run tests
      run: |
        pip install -r requirements.txt
        pytest --db=${{ matrix.database }}
```

##### **Canary Deployment Strategy**
```yaml
# Canary deployment workflow
canary-deployment:
  runs-on: ubuntu-latest
  steps:
    - name: Deploy to 10% of fleet
      run: |
        kubectl set image deployment/vehicle-control \
          vehicle-control=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:canary

        kubectl scale deployment vehicle-control --replicas=10

    - name: Monitor canary deployment
      run: |
        # Wait for deployment to stabilize
        kubectl rollout status deployment/vehicle-control --timeout=300s

        # Run smoke tests
        ./scripts/smoke-test.sh

    - name: Check metrics
      run: |
        # Query monitoring system for error rates, latency, etc.
        error_rate=$(curl -s "http://prometheus:9090/api/v1/query?query=error_rate_5m")
        if [ "$(echo "$error_rate > 0.05" | bc -l)" -eq 1 ]; then
          echo "Error rate too high, rolling back"
          kubectl rollout undo deployment/vehicle-control
          exit 1
        fi

    - name: Full deployment
      run: |
        kubectl set image deployment/vehicle-control \
          vehicle-control=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest

        kubectl scale deployment vehicle-control --replicas=100
```

## 9.3 Unit and Integration Testing (Pytest, Jest)

### Testing Philosophy: Quality Assurance Through Systematic Verification

Testing in complex systems like vehicle control platforms represents both an engineering discipline and a risk management strategy. Effective testing transforms uncertainty into confidence, providing systematic verification that systems behave as intended under diverse conditions.

#### Unit Testing with Pytest

##### **Backend Unit Testing Framework**
```python
# backend/tests/conftest.py - Test configuration
import pytest
import asyncio
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import get_db
from app.main import app

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_db():
    """Create test database."""
    engine = create_async_engine(
        "postgresql+asyncpg://test:test@localhost/test_db",
        echo=False,
    )

    async with engine.begin() as conn:
        # Create tables
        from app.models import Base
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        # Drop tables
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()

@pytest.fixture
async def db_session(test_db) -> AsyncGenerator[AsyncSession, None]:
    """Create database session for tests."""
    async_session = sessionmaker(test_db, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session

@pytest.fixture
async def client():
    """Create test client for FastAPI app."""
    from fastapi.testclient import TestClient
    return TestClient(app)

@pytest.fixture
async def authenticated_client(client, db_session):
    """Create authenticated test client."""
    # Create test user
    from app.crud.user import create_user
    from app.schemas.user import UserCreate

    user_data = UserCreate(
        email="test@example.com",
        password="testpassword",
        full_name="Test User"
    )

    user = await create_user(db_session, user_data)

    # Login to get token
    response = client.post("/auth/login", json={
        "username": user_data.email,
        "password": user_data.password
    })

    token = response.json()["access_token"]

    # Set authorization header
    client.headers = {"Authorization": f"Bearer {token}"}

    return client
```

##### **Comprehensive Unit Test Examples**
```python
# backend/tests/test_vehicle_service.py
import pytest
from unittest.mock import Mock, AsyncMock
from app.services.vehicle_service import VehicleService
from app.schemas.vehicle import VehicleCreate

class TestVehicleService:
    @pytest.fixture
    def mock_repository(self):
        return AsyncMock()

    @pytest.fixture
    def mock_mqtt_client(self):
        return AsyncMock()

    @pytest.fixture
    def service(self, mock_repository, mock_mqtt_client):
        return VehicleService(mock_repository, mock_mqtt_client)

    @pytest.mark.asyncio
    async def test_create_vehicle_success(self, service, mock_repository):
        """Test successful vehicle creation."""
        vehicle_data = VehicleCreate(
            external_id="BUS-001",
            type="electric_bus",
            manufacturer="TestManufacturer"
        )

        expected_vehicle = Mock(id="uuid-123", **vehicle_data.dict())

        mock_repository.create.return_value = expected_vehicle

        result = await service.create_vehicle(vehicle_data)

        assert result == expected_vehicle
        mock_repository.create.assert_called_once_with(vehicle_data)

    @pytest.mark.asyncio
    async def test_create_vehicle_duplicate_id(self, service, mock_repository):
        """Test vehicle creation with duplicate external ID."""
        vehicle_data = VehicleCreate(
            external_id="BUS-001",
            type="electric_bus"
        )

        mock_repository.create.side_effect = IntegrityError(
            "Duplicate external_id",
            None,
            None
        )

        with pytest.raises(HTTPException) as exc_info:
            await service.create_vehicle(vehicle_data)

        assert exc_info.value.status_code == 409
        assert "already exists" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_send_command_validates_permissions(self, service, mock_repository):
        """Test that command sending validates user permissions."""
        vehicle_id = "vehicle-123"
        command = {"type": "start_charging", "parameters": {}}

        # Mock vehicle exists
        mock_vehicle = Mock(id=vehicle_id, fleet_id="fleet-456")
        mock_repository.get_by_id.return_value = mock_vehicle

        # Mock permission check fails
        service._check_command_permissions = AsyncMock(return_value=False)

        with pytest.raises(HTTPException) as exc_info:
            await service.send_command(vehicle_id, command, user_id="user-789")

        assert exc_info.value.status_code == 403
        assert "permission" in str(exc_info.value.detail).lower()

    @pytest.mark.asyncio
    async def test_get_vehicle_telemetry_with_caching(self, service, mock_repository):
        """Test telemetry retrieval with caching."""
        vehicle_id = "vehicle-123"
        time_range = ("2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z")

        cached_data = [{"timestamp": "2023-01-01T12:00:00Z", "speed": 50}]
        service.cache.get = AsyncMock(return_value=cached_data)

        result = await service.get_vehicle_telemetry(vehicle_id, time_range)

        assert result == cached_data
        service.cache.get.assert_called_once()
        # Repository should not be called when cache hit
        mock_repository.get_telemetry.assert_not_called()

    @pytest.mark.asyncio
    async def test_bulk_vehicle_status_update(self, service, mock_repository, mock_mqtt_client):
        """Test bulk status update for multiple vehicles."""
        vehicle_updates = [
            {"id": "v1", "status": "active", "location": {"lat": 48.8, "lng": 2.3}},
            {"id": "v2", "status": "charging", "location": {"lat": 48.9, "lng": 2.4}},
        ]

        mock_repository.bulk_update_status.return_value = len(vehicle_updates)

        result = await service.bulk_update_vehicle_status(vehicle_updates)

        assert result == len(vehicle_updates)
        mock_repository.bulk_update_status.assert_called_once_with(vehicle_updates)

        # Verify MQTT notifications sent
        assert mock_mqtt_client.publish.call_count == len(vehicle_updates)
```

#### Frontend Testing with Jest

##### **React Component Testing**
```javascript
// frontend/src/components/__tests__/VehicleCard.test.js
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { jest } from '@jest/globals';
import VehicleCard from '../VehicleCard';

// Mock the API calls
jest.mock('../../api/vehicleApi');

describe('VehicleCard', () => {
  const mockVehicle = {
    id: 'bus-001',
    external_id: 'BUS-001',
    type: 'electric_bus',
    status: 'active',
    battery_level: 85,
    location: { lat: 48.8566, lng: 2.3522 },
    last_seen: '2023-01-01T12:00:00Z'
  };

  const mockOnCommand = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('renders vehicle information correctly', () => {
    render(<VehicleCard vehicle={mockVehicle} onCommand={mockOnCommand} />);

    expect(screen.getByText('BUS-001')).toBeInTheDocument();
    expect(screen.getByText('Electric Bus')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('85%')).toBeInTheDocument();
  });

  test('displays battery level with correct styling', () => {
    render(<VehicleCard vehicle={mockVehicle} onCommand={mockOnCommand} />);

    const batteryElement = screen.getByText('85%');
    expect(batteryElement).toHaveClass('battery-high'); // Assuming CSS classes for battery levels
  });

  test('shows command button when vehicle is online', () => {
    render(<VehicleCard vehicle={mockVehicle} onCommand={mockOnCommand} />);

    const commandButton = screen.getByRole('button', { name: /send command/i });
    expect(commandButton).toBeInTheDocument();
  });

  test('hides command button when vehicle is offline', () => {
    const offlineVehicle = { ...mockVehicle, status: 'offline' };

    render(<VehicleCard vehicle={offlineVehicle} onCommand={mockOnCommand} />);

    const commandButton = screen.queryByRole('button', { name: /send command/i });
    expect(commandButton).not.toBeInTheDocument();
  });

  test('calls onCommand when command button is clicked', async () => {
    render(<VehicleCard vehicle={mockVehicle} onCommand={mockOnCommand} />);

    const commandButton = screen.getByRole('button', { name: /send command/i });
    fireEvent.click(commandButton);

    await waitFor(() => {
      expect(mockOnCommand).toHaveBeenCalledWith(mockVehicle.id, expect.any(Object));
    });
  });

  test('displays location information', () => {
    render(<VehicleCard vehicle={mockVehicle} onCommand={mockOnCommand} />);

    expect(screen.getByText(/48\.8566, 2\.3522/)).toBeInTheDocument();
  });

  test('shows last seen timestamp', () => {
    render(<VehicleCard vehicle={mockVehicle} onCommand={mockOnCommand} />);

    expect(screen.getByText('Last seen:')).toBeInTheDocument();
    expect(screen.getByText('January 1, 2023 12:00 PM')).toBeInTheDocument();
  });
});

// frontend/src/components/__tests__/VehicleMap.test.js
import { render, screen } from '@testing-library/react';
import VehicleMap from '../VehicleMap';

describe('VehicleMap', () => {
  const mockVehicles = [
    {
      id: 'bus-001',
      location: { lat: 48.8566, lng: 2.3522 },
      status: 'active'
    },
    {
      id: 'bus-002',
      location: { lat: 48.8606, lng: 2.3376 },
      status: 'charging'
    }
  ];

  test('renders map container', () => {
    render(<VehicleMap vehicles={mockVehicles} />);
    const mapContainer = screen.getByRole('region', { name: /vehicle map/i });
    expect(mapContainer).toBeInTheDocument();
  });

  test('displays vehicle markers', () => {
    render(<VehicleMap vehicles={mockVehicles} />);

    // Check that vehicle markers are rendered
    mockVehicles.forEach(vehicle => {
      const marker = screen.getByTestId(`vehicle-marker-${vehicle.id}`);
      expect(marker).toBeInTheDocument();
    });
  });

  test('shows vehicle status in markers', () => {
    render(<VehicleMap vehicles={mockVehicles} />);

    const activeMarker = screen.getByTestId('vehicle-marker-bus-001');
    const chargingMarker = screen.getByTestId('vehicle-marker-bus-002');

    expect(activeMarker).toHaveClass('marker-active');
    expect(chargingMarker).toHaveClass('marker-charging');
  });
});
```

#### Integration Testing

##### **End-to-End Test Scenarios**
```python
# backend/tests/integration/test_vehicle_lifecycle.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.mark.integration
class TestVehicleLifecycle:
    """Test complete vehicle lifecycle from creation to decommissioning."""

    @pytest.mark.asyncio
    async def test_vehicle_creation_and_telemetry_flow(self, client: AsyncClient, db_session: AsyncSession):
        """Test complete flow from vehicle creation to telemetry ingestion."""
        # 1. Create vehicle
        vehicle_data = {
            "external_id": "TEST-BUS-001",
            "type": "electric_bus",
            "manufacturer": "TestManufacturer",
            "model": "TestModel"
        }

        response = await client.post("/api/v1/vehicles", json=vehicle_data)
        assert response.status_code == 201

        vehicle = response.json()
        vehicle_id = vehicle["id"]

        # 2. Verify vehicle was created in database
        from app.crud.vehicle import get_vehicle
        db_vehicle = await get_vehicle(db_session, vehicle_id)
        assert db_vehicle is not None
        assert db_vehicle.external_id == vehicle_data["external_id"]

        # 3. Send telemetry data
        telemetry_data = {
            "vehicle_id": vehicle_id,
            "timestamp": "2023-01-01T12:00:00Z",
            "sensors": {
                "battery_voltage": 400.5,
                "battery_current": -15.2,
                "motor_temperature": 65.3,
                "vehicle_speed": 45.8
            }
        }

        response = await client.post("/api/v1/telemetry", json=telemetry_data)
        assert response.status_code == 202  # Accepted for async processing

        # 4. Verify telemetry was stored
        await asyncio.sleep(0.1)  # Allow async processing

        response = await client.get(f"/api/v1/vehicles/{vehicle_id}/telemetry")
        assert response.status_code == 200

        telemetry = response.json()
        assert len(telemetry) > 0

        latest_reading = telemetry[0]
        assert latest_reading["battery_voltage"] == 400.5
        assert latest_reading["vehicle_speed"] == 45.8

    @pytest.mark.asyncio
    async def test_vehicle_command_execution(self, client: AsyncClient):
        """Test vehicle command creation and execution flow."""
        # Create vehicle first
        vehicle_data = {
            "external_id": "CMD-TEST-001",
            "type": "electric_bus"
        }

        response = await client.post("/api/v1/vehicles", json=vehicle_data)
        vehicle_id = response.json()["id"]

        # Send command
        command_data = {
            "type": "set_charging_limit",
            "parameters": {
                "max_current": 32.0,
                "max_voltage": 400.0
            }
        }

        response = await client.post(f"/api/v1/vehicles/{vehicle_id}/commands", json=command_data)
        assert response.status_code == 202

        command = response.json()
        command_id = command["id"]

        # Check command status
        response = await client.get(f"/api/v1/commands/{command_id}")
        assert response.status_code == 200

        command_status = response.json()
        assert command_status["status"] in ["pending", "sent", "acknowledged"]

        # Simulate command acknowledgment (normally done by agent)
        await self._simulate_command_acknowledgment(command_id)

        # Verify command completion
        response = await client.get(f"/api/v1/commands/{command_id}")
        command_status = response.json()
        assert command_status["status"] == "completed"

    async def _simulate_command_acknowledgment(self, command_id: str):
        """Simulate agent acknowledging command receipt."""
        # In real implementation, this would be done by the IoT agent
        # For testing, we directly update the command status
        from app.crud.command import update_command_status

        await update_command_status(
            db_session=None,  # Would need proper session
            command_id=command_id,
            status="acknowledged",
            result={"agent_id": "test-agent", "timestamp": "2023-01-01T12:00:00Z"}
        )

    @pytest.mark.asyncio
    async def test_fleet_dashboard_data_aggregation(self, client: AsyncClient):
        """Test fleet dashboard data aggregation."""
        # Create multiple vehicles
        vehicles = []
        for i in range(5):
            vehicle_data = {
                "external_id": f"FLEET-TEST-{i:03d}",
                "type": "electric_bus",
                "fleet_id": "test-fleet"
            }

            response = await client.post("/api/v1/vehicles", json=vehicle_data)
            vehicles.append(response.json())

        # Send telemetry for each vehicle
        for vehicle in vehicles:
            telemetry_data = {
                "vehicle_id": vehicle["id"],
                "timestamp": "2023-01-01T12:00:00Z",
                "sensors": {
                    "battery_level": 80 + (vehicle["id"][-1] * 2),  # Vary battery levels
                    "vehicle_speed": 30 + (vehicle["id"][-1] * 5),
                    "motor_temperature": 60 + vehicle["id"][-1]
                }
            }

            await client.post("/api/v1/telemetry", json=telemetry_data)

        # Allow processing time
        await asyncio.sleep(0.2)

        # Get fleet dashboard data
        response = await client.get("/api/v1/fleet/test-fleet/dashboard")
        assert response.status_code == 200

        dashboard_data = response.json()

        # Verify aggregation
        assert "vehicle_count" in dashboard_data
        assert dashboard_data["vehicle_count"] == 5

        assert "average_battery_level" in dashboard_data
        assert 80 <= dashboard_data["average_battery_level"] <= 90

        assert "active_vehicles" in dashboard_data
        assert dashboard_data["active_vehicles"] == 5

        # Verify vehicle list
        assert "vehicles" in dashboard_data
        assert len(dashboard_data["vehicles"]) == 5

        # Check individual vehicle data
        for vehicle_data in dashboard_data["vehicles"]:
            assert "id" in vehicle_data
            assert "battery_level" in vehicle_data
            assert "status" in vehicle_data
```

## 9.4 Automated Documentation (Swagger / Redoc)

### API Documentation: The User Manual for Developers

Automated API documentation transforms code into comprehensive, interactive developer resources. Just as a vehicle's manual provides instructions for operation, API documentation provides the interface contract for software integration.

#### OpenAPI/Swagger Integration

##### **FastAPI Automatic Documentation Generation**
```python
# backend/app/main.py - FastAPI with comprehensive documentation
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

app = FastAPI(
    title="OpenVehicleControl API",
    description="""
    ## OpenVehicleControl API

    Comprehensive API for electric vehicle fleet management, real-time telemetry,
    and connected mobility infrastructure.

    ### Key Features
    - Real-time vehicle telemetry and control
    - Fleet management and analytics
    - Secure command execution with digital signatures
    - Multi-protocol support (MQTT, WebSocket, REST)
    - Comprehensive security and authentication

    ### Authentication
    All API endpoints require authentication via JWT tokens obtained through `/auth/login`.

    ### Rate Limiting
    API calls are rate-limited to prevent abuse. Limits vary by endpoint and user role.
    """,
    version="1.0.0",
    openapi_tags=[
        {
            "name": "vehicles",
            "description": "Vehicle management operations"
        },
        {
            "name": "telemetry",
            "description": "Telemetry data operations"
        },
        {
            "name": "commands",
            "description": "Vehicle command operations"
        },
        {
            "name": "auth",
            "description": "Authentication operations"
        }
    ],
    docs_url="/docs",  # Swagger UI
    redoc_url="/redoc"  # ReDoc
)

# Security scheme definition
security = HTTPBearer()

# Pydantic models with comprehensive documentation
class VehicleBase(BaseModel):
    external_id: str = Field(
        ...,
        description="Unique external identifier for the vehicle",
        example="BUS-001",
        max_length=50
    )
    type: str = Field(
        ...,
        description="Vehicle type classification",
        example="electric_bus",
        enum=["electric_bus", "delivery_van", "scooter", "personal_car"]
    )
    manufacturer: Optional[str] = Field(
        None,
        description="Vehicle manufacturer",
        example="BYD",
        max_length=100
    )
    model: Optional[str] = Field(
        None,
        description="Vehicle model",
        example="K9S",
        max_length=100
    )

class VehicleCreate(VehicleBase):
    pass

class Vehicle(VehicleBase):
    id: str = Field(
        ...,
        description="Internal unique identifier",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    status: str = Field(
        "unknown",
        description="Current vehicle status",
        example="active",
        enum=["active", "inactive", "maintenance", "offline", "unknown"]
    )
    battery_level: Optional[float] = Field(
        None,
        description="Current battery level (0-100%)",
        ge=0,
        le=100,
        example=85.5
    )
    location: Optional[dict] = Field(
        None,
        description="Current vehicle location",
        example={"lat": 48.8566, "lng": 2.3522}
    )
    last_seen: Optional[datetime] = Field(
        None,
        description="Timestamp of last communication"
    )
    created_at: datetime
    updated_at: datetime

class TelemetryData(BaseModel):
    vehicle_id: str = Field(
        ...,
        description="Vehicle identifier",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    timestamp: datetime = Field(
        ...,
        description="Telemetry timestamp (ISO 8601)",
        example="2023-01-01T12:00:00Z"
    )
    sensors: dict = Field(
        ...,
        description="Sensor readings as key-value pairs",
        example={
            "battery_voltage": 401.5,
            "battery_current": -12.3,
            "motor_temperature": 68.4,
            "vehicle_speed": 45.2
        }
    )

class CommandRequest(BaseModel):
    type: str = Field(
        ...,
        description="Command type",
        example="set_charging_limit",
        enum=[
            "start_charging", "stop_charging", "set_charging_limit",
            "set_speed_limit", "send_diagnostic_command", "reboot_system"
        ]
    )
    parameters: dict = Field(
        default_factory=dict,
        description="Command-specific parameters",
        example={"max_current": 32.0, "max_voltage": 400.0}
    )
    priority: str = Field(
        "normal",
        description="Command priority level",
        enum=["low", "normal", "high", "critical"]
    )
    timeout: Optional[int] = Field(
        30,
        description="Command timeout in seconds",
        ge=5,
        le=300
    )

# API endpoints with comprehensive documentation
@app.post(
    "/api/v1/vehicles",
    response_model=Vehicle,
    tags=["vehicles"],
    summary="Create new vehicle",
    description="""
    Register a new vehicle in the system.

    This endpoint creates a new vehicle record and initializes its configuration.
    The vehicle will be assigned a unique internal ID and can immediately receive
    commands and telemetry data.

    **Required permissions:** vehicle_admin, fleet_admin
    """,
    responses={
        201: {"description": "Vehicle created successfully"},
        409: {"description": "Vehicle with this external_id already exists"},
        422: {"description": "Invalid vehicle data"}
    }
)
async def create_vehicle(
    vehicle: VehicleCreate,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: dict = Depends(get_current_user)
):
    """Create a new vehicle."""
    # Implementation here
    pass

@app.get(
    "/api/v1/vehicles",
    response_model=List[Vehicle],
    tags=["vehicles"],
    summary="List vehicles",
    description="""
    Retrieve a paginated list of vehicles with optional filtering.

    Results can be filtered by type, status, fleet, and other criteria.
    Use query parameters for pagination and sorting.
    """,
    responses={
        200: {"description": "Vehicles retrieved successfully"}
    }
)
async def list_vehicles(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    type_filter: Optional[str] = Query(None, description="Filter by vehicle type"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    search: Optional[str] = Query(None, description="Search in external_id and manufacturer"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", enum=["asc", "desc"], description="Sort order"),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: dict = Depends(get_current_user)
):
    """List vehicles with filtering and pagination."""
    # Implementation here
    pass

@app.post(
    "/api/v1/telemetry",
    tags=["telemetry"],
    summary="Submit telemetry data",
    description="""
    Submit telemetry data from vehicles or IoT agents.

    Data is processed asynchronously and stored in time-series database.
    High-volume submissions are batched for optimal performance.
    """,
    responses={
        202: {"description": "Telemetry data accepted for processing"},
        400: {"description": "Invalid telemetry data format"},
        429: {"description": "Rate limit exceeded"}
    }
)
async def submit_telemetry(
    telemetry: TelemetryData,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Submit vehicle telemetry data."""
    # Implementation here
    pass

@app.post(
    "/api/v1/vehicles/{vehicle_id}/commands",
    tags=["commands"],
    summary="Send command to vehicle",
    description="""
    Send a command to a specific vehicle for execution.

    Commands are digitally signed and queued for delivery.
    Command execution status can be monitored via the returned command ID.
    """,
    responses={
        202: {"description": "Command queued for execution"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Vehicle not found"},
        422: {"description": "Invalid command parameters"}
    }
)
async def send_vehicle_command(
    vehicle_id: str,
    command: CommandRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: dict = Depends(get_current_user)
):
    """Send command to vehicle."""
    # Implementation here
    pass
```

#### Custom OpenAPI Extensions

##### **Enhanced API Documentation**
```python
# backend/app/docs_extensions.py
from fastapi.openapi.utils import get_openapi
from fastapi import FastAPI

def custom_openapi(app: FastAPI):
    """Customize OpenAPI schema with extensions."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Add custom extensions
    openapi_schema["x-logo"] = {
        "url": "https://openvehiclecontrol.org/logo.png",
        "altText": "OpenVehicleControl Logo"
    }

    # Add security scheme extensions
    openapi_schema["components"]["securitySchemes"]["JWTBearer"]["x-tokenInfoFunc"] = {
        "func": "app.auth.get_token_info"
    }

    # Add custom response examples
    for path_item in openapi_schema["paths"].values():
        for operation in path_item.values():
            if "responses" in operation:
                for response_code, response in operation["responses"].items():
                    if response_code.startswith("2"):
                        response["x-success-example"] = {
                            "message": "Operation completed successfully"
                        }
                    elif response_code.startswith("4"):
                        response["x-error-example"] = {
                            "error": "Request validation failed",
                            "details": ["field 'name' is required"]
                        }

    # Add rate limiting information
    openapi_schema["x-rate-limits"] = {
        "default": "1000 requests per hour",
        "authenticated": "10000 requests per hour",
        "admin": "unlimited"
    }

    # Add changelog
    openapi_schema["x-changelog"] = [
        {
            "version": "1.0.0",
            "date": "2023-01-01",
            "changes": ["Initial API release"]
        }
    ]

    app.openapi_schema = openapi_schema
    return openapi_schema

# Apply custom OpenAPI generation
app.openapi = lambda: custom_openapi(app)
```

#### Documentation Deployment

##### **Multi-Format Documentation Generation**
```python
# backend/scripts/generate_docs.py
import json
import yaml
from fastapi.openapi.utils import get_openapi
from app.main import app

def generate_openapi_specs():
    """Generate OpenAPI specifications in multiple formats."""

    # Get OpenAPI schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Generate JSON specification
    with open("docs/openapi.json", "w") as f:
        json.dump(openapi_schema, f, indent=2)

    # Generate YAML specification
    with open("docs/openapi.yaml", "w") as f:
        yaml.dump(openapi_schema, f, default_flow_style=False)

    print("OpenAPI specifications generated successfully")

def generate_postman_collection():
    """Generate Postman collection for API testing."""

    # Convert OpenAPI to Postman collection format
    # Implementation would use a library like openapi-to-postman

    collection = {
        "info": {
            "name": "OpenVehicleControl API",
            "description": "API collection for testing OpenVehicleControl endpoints",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [],
        "variable": [
            {
                "key": "baseUrl",
                "value": "http://localhost:8000",
                "type": "string"
            },
            {
                "key": "authToken",
                "value": "",
                "type": "string"
            }
        ]
    }

    # Convert OpenAPI paths to Postman requests
    openapi_schema = app.openapi()

    for path, path_item in openapi_schema["paths"].items():
        for method, operation in path_item.items():
            request = {
                "name": operation.get("summary", path),
                "request": {
                    "method": method.upper(),
                    "header": [
                        {
                            "key": "Content-Type",
                            "value": "application/json"
                        },
                        {
                            "key": "Authorization",
                            "value": "Bearer {{authToken}}",
                            "description": "JWT Bearer token"
                        }
                    ],
                    "url": {
                        "raw": "{{baseUrl}}" + path,
                        "host": ["{{baseUrl}}"],
                        "path": path.split("/")[1:]
                    }
                }
            }

            collection["item"].append(request)

    with open("docs/postman_collection.json", "w") as f:
        json.dump(collection, f, indent=2)

    print("Postman collection generated successfully")

if __name__ == "__main__":
    generate_openapi_specs()
    generate_postman_collection()
```

## 9.5 System Monitoring (Prometheus)

### System Monitoring: Observability for Complex Systems

Monitoring in distributed systems like OpenVehicleControl provides visibility into system health, performance, and reliability. Effective monitoring transforms reactive firefighting into proactive system management.

#### Prometheus Metrics Architecture

##### **Metrics Collection Strategy**
```python
# backend/app/monitoring/metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import time

# Application metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'active_connections',
    'Number of active connections'
)

VEHICLE_COUNT = Gauge(
    'vehicles_registered_total',
    'Total number of registered vehicles'
)

TELEMETRY_RATE = Counter(
    'telemetry_messages_total',
    'Total telemetry messages processed',
    ['vehicle_type', 'protocol']
)

COMMAND_SUCCESS_RATE = Counter(
    'command_executions_total',
    'Total command executions',
    ['command_type', 'status']
)

DATABASE_CONNECTIONS = Gauge(
    'database_connections_active',
    'Number of active database connections',
    ['pool']
)

MQTT_CONNECTIONS = Gauge(
    'mqtt_connections_active',
    'Number of active MQTT connections'
)

# Business metrics
FLEET_UTILIZATION = Gauge(
    'fleet_utilization_percentage',
    'Fleet utilization percentage'
)

AVERAGE_BATTERY_LEVEL = Gauge(
    'average_battery_level_percentage',
    'Average fleet battery level'
)

ACTIVE_CHARGING_SESSIONS = Gauge(
    'charging_sessions_active',
    'Number of active charging sessions'
)

class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to collect HTTP metrics."""

    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path

        # Start timer
        start_time = time.time()

        # Count request
        REQUEST_COUNT.labels(method=method, endpoint=path, status_code='processing').inc()

        try:
            response = await call_next(request)

            # Record latency
            latency = time.time() - start_time
            REQUEST_LATENCY.labels(method=method, endpoint=path).observe(latency)

            # Update status code
            REQUEST_COUNT.labels(method=method, endpoint=path, status_code=response.status_code).inc()
            REQUEST_COUNT.labels(method=method, endpoint=path, status_code='processing').dec()

            return response

        except Exception as e:
            # Record error
            REQUEST_COUNT.labels(method=method, endpoint=path, status_code='500').inc()
            REQUEST_COUNT.labels(method=method, endpoint=path, status_code='processing').dec()

            raise

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        generate_latest(),
        media_type="text/plain; charset=utf-8"
    )
```

#### Custom Metrics Collectors

##### **Business Logic Metrics**
```python
# backend/app/monitoring/business_metrics.py
from app.monitoring.metrics import *
import asyncio

class BusinessMetricsCollector:
    def __init__(self, vehicle_service, telemetry_service, command_service):
        self.vehicle_service = vehicle_service
        self.telemetry_service = telemetry_service
        self.command_service = command_service

    async def collect_business_metrics(self):
        """Collect and update business metrics."""
        while True:
            try:
                await self._update_vehicle_metrics()
                await self._update_telemetry_metrics()
                await self._update_command_metrics()
                await self._update_fleet_metrics()

            except Exception as e:
                logger.error(f"Error collecting business metrics: {e}")

            await asyncio.sleep(60)  # Update every minute

    async def _update_vehicle_metrics(self):
        """Update vehicle-related metrics."""
        try:
            # Get total vehicle count
            total_vehicles = await self.vehicle_service.get_total_vehicle_count()
            VEHICLE_COUNT.set(total_vehicles)

            # Get vehicles by status
            status_counts = await self.vehicle_service.get_vehicle_status_counts()
            for status, count in status_counts.items():
                # Create dynamic metrics for each status
                metric_name = f'vehicles_status_{status}'
                if not hasattr(self, metric_name):
                    setattr(self, metric_name, Gauge(
                        f'vehicles_status_{status}',
                        f'Number of vehicles with status {status}'
                    ))
                getattr(self, metric_name).set(count)

        except Exception as e:
            logger.error(f"Error updating vehicle metrics: {e}")

    async def _update_telemetry_metrics(self):
        """Update telemetry processing metrics."""
        try:
            # Get telemetry rates by protocol
            rates = await self.telemetry_service.get_telemetry_rates()

            for protocol, rate in rates.items():
                TELEMETRY_RATE.labels(vehicle_type='all', protocol=protocol)._value_set(rate)

        except Exception as e:
            logger.error(f"Error updating telemetry metrics: {e}")

    async def _update_command_metrics(self):
        """Update command execution metrics."""
        try:
            # Get command success rates
            success_rates = await self.command_service.get_command_success_rates()

            for command_type, stats in success_rates.items():
                COMMAND_SUCCESS_RATE.labels(
                    command_type=command_type,
                    status='success'
                )._value_set(stats['success'])

                COMMAND_SUCCESS_RATE.labels(
                    command_type=command_type,
                    status='failure'
                )._value_set(stats['failure'])

        except Exception as e:
            logger.error(f"Error updating command metrics: {e}")

    async def _update_fleet_metrics(self):
        """Update fleet-level business metrics."""
        try:
            # Calculate fleet utilization
            utilization = await self.vehicle_service.calculate_fleet_utilization()
            FLEET_UTILIZATION.set(utilization)

            # Calculate average battery level
            avg_battery = await self.telemetry_service.get_average_battery_level()
            AVERAGE_BATTERY_LEVEL.set(avg_battery)

            # Get active charging sessions
            active_charging = await self.vehicle_service.get_active_charging_sessions()
            ACTIVE_CHARGING_SESSIONS.set(active_charging)

        except Exception as e:
            logger.error(f"Error updating fleet metrics: {e}")

# Start metrics collection
metrics_collector = BusinessMetricsCollector(vehicle_service, telemetry_service, command_service)
asyncio.create_task(metrics_collector.collect_business_metrics())
```

#### Alerting Rules

##### **Prometheus Alerting Configuration**
```yaml
# prometheus/alert_rules.yml
groups:
  - name: openvehiclecontrol.alerts
    rules:
      # System health alerts
      - alert: HighErrorRate
        expr: rate(http_requests_total{status_code=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | printf \"%.2f\" }}% over the last 5 minutes"

      - alert: DatabaseConnectionsHigh
        expr: database_connections_active > 80
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "High database connection usage"
          description: "Database connections at {{ $value }}% capacity"

      # Business alerts
      - alert: LowFleetUtilization
        expr: fleet_utilization_percentage < 70
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Low fleet utilization"
          description: "Fleet utilization is {{ $value | printf \"%.1f\" }}%"

      - alert: BatteryLevelsCritical
        expr: average_battery_level_percentage < 15
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Critical battery levels across fleet"
          description: "Average battery level is {{ $value | printf \"%.1f\" }}%"

      - alert: VehicleOffline
        expr: up{job="vehicle_agent"} == 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Vehicle agent offline"
          description: "Vehicle {{ $labels.instance }} has been offline for 10 minutes"

      # Security alerts
      - alert: AuthenticationFailures
        expr: rate(authentication_failures_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "Authentication failures: {{ $value | printf \"%.0f\" }}/min"

      - alert: CommandSignatureVerificationFailures
        expr: rate(command_signature_verification_failures_total[5m]) > 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Command signature verification failures"
          description: "Command signature failures: {{ $value | printf \"%.0f\" }}/min"
```

#### Grafana Dashboards

##### **Monitoring Dashboard Configuration**
```json
// grafana/dashboards/system_monitoring.json
{
  "dashboard": {
    "title": "System Monitoring",
    "tags": ["monitoring", "system"],
    "timezone": "UTC",
    "panels": [
      {
        "title": "HTTP Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "(rate(http_requests_total{status_code=~\"5..\"}[5m]) / rate(http_requests_total[5m])) * 100",
            "format": "percent"
          }
        ],
        "thresholds": {
          "mode": "absolute",
          "steps": [
            { "value": null, "color": "green" },
            { "value": 5, "color": "orange" },
            { "value": 10, "color": "red" }
          ]
        }
      },
      {
        "title": "Database Performance",
        "type": "table",
        "targets": [
          {
            "expr": "database_connections_active",
            "format": "table"
          }
        ]
      },
      {
        "title": "Fleet Health Overview",
        "type": "bargauge",
        "targets": [
          {
            "expr": "vehicles_registered_total",
            "legendFormat": "Total Vehicles"
          },
          {
            "expr": "vehicles_status_active",
            "legendFormat": "Active Vehicles"
          },
          {
            "expr": "charging_sessions_active",
            "legendFormat": "Charging Sessions"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
```

## 9.6 Centralized Logging (ELK or Loki)

### Centralized Logging: Making Sense of Distributed Systems

Centralized logging provides the comprehensive view needed to understand complex distributed systems. Just as a conductor needs to hear all orchestra sections simultaneously, centralized logging enables correlation of events across all system components.

#### ELK Stack Implementation

##### **Logstash Configuration for OpenVehicleControl**
```ruby
# logstash/pipeline/vehicle_logs.conf
input {
  # Application logs from containers
  docker {
    container_logs => true
    exclude_containers => ["logstash"]
  }

  # System logs
  syslog {
    port => 514
    type => "system"
  }

  # MQTT message logs
  tcp {
    port => 1514
    codec => json
    type => "mqtt_logs"
  }
}

filter {
  # Parse JSON logs
  if [message] =~ /^\{/ {
    json {
      source => "message"
    }
  }

  # Extract timestamp
  date {
    match => ["timestamp", "ISO8601", "yyyy-MM-dd HH:mm:ss", "dd/MMM/yyyy:HH:mm:ss Z"]
    target => "@timestamp"
  }

  # Add service identification
  if [docker][container][name] {
    mutate {
      add_field => { "service" => "%{[docker][container][name]}" }
    }
  }

  # Parse log levels
  grok {
    match => { "message" => "%{LOGLEVEL:log_level} %{GREEDYDATA:log_message}" }
    patterns_dir => ["/etc/logstash/patterns"]
  }

  # Extract vehicle IDs from logs
  grok {
    match => { "message" => "vehicle\[(?<vehicle_id>[^\]]+)\]" }
    tag_on_failure => []
  }

  # GeoIP enrichment for IP addresses
  geoip {
    source => "client_ip"
    target => "geoip"
  }

  # Anonymize sensitive data
  mutate {
    gsub => [
      "message", "(password|token|key)\s*[:=]\s*[^\s]+", "\\1:= [REDACTED]"
    ]
  }
}

output {
  # Primary Elasticsearch output
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "openvehiclecontrol-%{+YYYY.MM.dd}"
    template => "/etc/logstash/templates/vehicle_logs.json"
    template_name => "vehicle_logs"
    template_overwrite => true
  }

  # Archive to S3 for long-term storage
  s3 {
    access_key_id => "${AWS_ACCESS_KEY}"
    secret_access_key => "${AWS_SECRET_KEY}"
    region => "${AWS_REGION}"
    bucket => "ovc-logs-archive"
    prefix => "logs/%{+YYYY}/%{+MM}/%{+dd}/"
    rotation_strategy => "time"
    time_rotate => 15
    codec => "gzip"
  }

  # Error logs to separate index
  if [log_level] == "ERROR" or [log_level] == "CRITICAL" {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "openvehiclecontrol-errors-%{+YYYY.MM.dd}"
    }
  }
}
```

##### **Elasticsearch Index Templates**
```json
// logstash/templates/vehicle_logs.json
{
  "index_patterns": ["openvehiclecontrol-*"],
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1,
    "refresh_interval": "30s",
    "index.codec": "best_compression"
  },
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "service": {
        "type": "keyword"
      },
      "log_level": {
        "type": "keyword"
      },
      "vehicle_id": {
        "type": "keyword",
        "index": true
      },
      "fleet_id": {
        "type": "keyword"
      },
      "message": {
        "type": "text",
        "analyzer": "standard"
      },
      "error_code": {
        "type": "keyword"
      },
      "request_id": {
        "type": "keyword"
      },
      "user_id": {
        "type": "keyword"
      },
      "client_ip": {
        "type": "ip"
      },
      "geoip": {
        "properties": {
          "country_name": { "type": "keyword" },
          "city_name": { "type": "keyword" },
          "location": { "type": "geo_point" }
        }
      },
      "performance_metrics": {
        "properties": {
          "response_time": { "type": "float" },
          "memory_usage": { "type": "long" },
          "cpu_usage": { "type": "float" }
        }
      },
      "business_events": {
        "properties": {
          "event_type": { "type": "keyword" },
          "entity_type": { "type": "keyword" },
          "entity_id": { "type": "keyword" },
          "action": { "type": "keyword" }
        }
      }
    }
  }
}
```

#### Kibana Dashboards for Log Analysis

##### **Log Analysis Dashboard Configuration**
```json
// kibana/dashboards/log_analysis.json
{
  "objects": [
    {
      "type": "dashboard",
      "id": "log-analysis-dashboard",
      "attributes": {
        "title": "Log Analysis Dashboard",
        "description": "Comprehensive log analysis for OpenVehicleControl",
        "panelsJSON": [
          {
            "id": "error-rate-chart",
            "title": "Error Rate Over Time",
            "type": "area",
            "indexPatternId": "openvehiclecontrol-*",
            "series": [
              {
                "label": "Error Rate",
                "metrics": [
                  {
                    "type": "count",
                    "field": "log_level",
                    "filters": [
                      { "query": "log_level:ERROR OR log_level:CRITICAL" }
                    ]
                  }
                ],
                "timeField": "@timestamp"
              }
            ]
          },
          {
            "id": "service-health-table",
            "title": "Service Health Status",
            "type": "table",
            "indexPatternId": "openvehiclecontrol-*",
            "columns": [
              {
                "field": "service",
                "label": "Service"
              },
              {
                "field": "log_level",
                "label": "Last Log Level",
                "aggregation": "terms"
              },
              {
                "field": "@timestamp",
                "label": "Last Seen",
                "aggregation": "max"
              }
            ],
            "query": {
              "bool": {
                "must": [
                  {
                    "range": {
                      "@timestamp": {
                        "gte": "now-1h"
                      }
                    }
                  }
                ]
              }
            }
          },
          {
            "id": "vehicle-error-heatmap",
            "title": "Vehicle Error Heatmap",
            "type": "heatmap",
            "indexPatternId": "openvehiclecontrol-*",
            "xAxisField": "@timestamp",
            "yAxisField": "vehicle_id",
            "valueField": "count",
            "query": {
              "term": { "log_level": "ERROR" }
            }
          }
        ]
      }
    }
  ]
}
```

#### Loki Alternative Implementation

##### **Loki for Cost-Effective Log Aggregation**
```yaml
# loki-config.yaml
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s

storage_config:
  filesystem:
    directory: /tmp/loki/chunks

schema_config:
  configs:
  - from: 2020-10-24
    store: boltdb-shipper
    object_store: filesystem
    schema: v11
    index:
      prefix: index_
      period: 24h

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: false
  retention_period: 0s
```

##### **Promtail Configuration for Log Shipping**
```yaml
# promtail-config.yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex: '/(.*)'
        target_label: 'container_name'
      - source_labels: ['__meta_docker_container_name']
        regex: '/(.*)'
        target_label: '__service__'
    pipeline_stages:
      - json:
          expressions:
            timestamp: timestamp
            level: level
            message: message
            vehicle_id: vehicle_id
      - labels:
          service: __service__
          vehicle_id:
      - timestamp:
          source: timestamp
          format: RFC3339Nano
      - output:
          source: message

  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: system
          host: ${HOSTNAME}
    pipeline_stages:
      - drop:
          source: "__path__"
          expression: "/var/log/docker/*"
      - match:
          selector: '{job="system"}'
          stages:
            - regex:
                expression: '^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\w+)\s+(?P<process>\w+)\[(?P<pid>\d+)\]:\s+(?P<message>.+)$'
            - timestamp:
                source: timestamp
                format: "Jan 2 15:04:05"
            - output:
                source: message
```

This comprehensive development and deployment toolkit establishes OpenVehicleControl as a production-ready platform with enterprise-grade observability, testing, and operational capabilities. The combination of containerization, CI/CD, monitoring, and centralized logging creates a robust foundation for managing complex vehicle control systems at scale.
