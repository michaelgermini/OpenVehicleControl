# 🧮 Chapter 8: Data and Analytics

## 8.1 Telemetry Modeling

### Data Modeling: From Raw Signals to Actionable Insights

Effective telemetry modeling transforms the chaotic flow of sensor data into structured, meaningful information. Think of this as the difference between hearing random noise versus understanding a symphony - the same data, but properly modeled, reveals patterns, trends, and actionable intelligence.

#### Telemetry Data Architecture

##### **Multi-Layer Data Modeling**
The telemetry system employs a hierarchical data model that serves different analytical needs:

```
Raw Data Layer (Sensor Readings)
├── Processed Data Layer (Validated & Enriched)
├── Aggregated Data Layer (Statistical Summaries)
├── Analytical Data Layer (Derived Metrics & KPIs)
└── Presentation Layer (Visualizations & Reports)
```

**Implementation:**
```python
# Telemetry data model hierarchy
class TelemetryDataModel:
    def __init__(self, schema_validator, enrichment_engine, aggregation_engine):
        self.validator = schema_validator
        self.enricher = enrichment_engine
        self.aggregator = aggregation_engine

    async def process_telemetry_stream(self, raw_data_stream):
        """Process streaming telemetry data through all layers"""
        async for raw_packet in raw_data_stream:
            # Layer 1: Raw Data Processing
            validated_data = await self._process_raw_data(raw_packet)

            # Layer 2: Data Enrichment
            enriched_data = await self._enrich_data(validated_data)

            # Layer 3: Real-time Aggregation
            aggregated_data = await self._aggregate_data(enriched_data)

            # Layer 4: Analytical Processing
            analytical_insights = await self._generate_analytics(aggregated_data)

            # Layer 5: Presentation Preparation
            presentation_data = await self._prepare_presentation(analytical_insights)

            yield presentation_data

    async def _process_raw_data(self, raw_packet: dict) -> ValidatedTelemetry:
        """Process and validate raw telemetry data"""
        # Validate data structure
        is_valid, validation_errors = await self.validator.validate_telemetry(raw_packet)

        if not is_valid:
            await self._handle_validation_error(raw_packet, validation_errors)
            return None

        # Convert to internal data model
        validated = ValidatedTelemetry(
            vehicle_id=raw_packet['vehicle_id'],
            timestamp=datetime.fromisoformat(raw_packet['timestamp']),
            sensor_readings=raw_packet['sensors'],
            metadata={
                'protocol_version': raw_packet.get('protocol_version', '1.0'),
                'quality_score': self._calculate_data_quality(raw_packet),
                'anomalies': []
            }
        )

        return validated

    async def _enrich_data(self, validated_data: ValidatedTelemetry) -> EnrichedTelemetry:
        """Enrich telemetry data with contextual information"""
        enriched = EnrichedTelemetry.from_validated(validated_data)

        # Add vehicle context
        vehicle_context = await self.enricher.get_vehicle_context(validated_data.vehicle_id)
        enriched.vehicle_info = vehicle_context

        # Add environmental data
        env_data = await self.enricher.get_environmental_data(
            validated_data.timestamp,
            vehicle_context.get('location')
        )
        enriched.environmental_data = env_data

        # Add operational context
        operational_context = await self.enricher.get_operational_context(
            validated_data.vehicle_id,
            validated_data.timestamp
        )
        enriched.operational_context = operational_context

        # Calculate derived metrics
        enriched.derived_metrics = await self._calculate_derived_metrics(validated_data)

        return enriched

    async def _calculate_derived_metrics(self, data: ValidatedTelemetry) -> dict:
        """Calculate derived metrics from raw sensor data"""
        metrics = {}

        # Energy efficiency metrics
        if 'battery_voltage' in data.sensor_readings and 'battery_current' in data.sensor_readings:
            voltage = data.sensor_readings['battery_voltage']
            current = data.sensor_readings['battery_current']

            # Power consumption
            metrics['power_consumption'] = voltage * current

            # Energy efficiency (simplified)
            if 'vehicle_speed' in data.sensor_readings:
                speed = data.sensor_readings['vehicle_speed']
                metrics['energy_efficiency'] = speed / max(abs(current), 0.1) if current != 0 else 0

        # Thermal management metrics
        if 'motor_temperature' in data.sensor_readings and 'ambient_temperature' in data.sensor_readings:
            motor_temp = data.sensor_readings['motor_temperature']
            ambient_temp = data.sensor_readings['ambient_temperature']

            metrics['thermal_gradient'] = motor_temp - ambient_temp
            metrics['cooling_efficiency'] = 1 / (1 + max(0, motor_temp - 80) / 40)

        # Performance metrics
        if 'engine_rpm' in data.sensor_readings and 'vehicle_speed' in data.sensor_readings:
            rpm = data.sensor_readings['engine_rpm']
            speed = data.sensor_readings['vehicle_speed']

            # Calculate optimal gear (simplified)
            optimal_rpm = speed * 30  # Rough approximation
            metrics['gear_efficiency'] = 1 - abs(rpm - optimal_rpm) / optimal_rpm

        return metrics
```

#### Time-Series Data Schema

##### **Temporal Data Modeling**
Time-series data requires specialized modeling for efficient storage and querying:

```python
# Time-series telemetry schema
class TimeSeriesTelemetry:
    def __init__(self, measurement_name: str, tags: dict, fields: dict, timestamp: datetime):
        self.measurement = measurement_name  # e.g., "vehicle_telemetry"
        self.tags = tags  # Indexed metadata (vehicle_id, sensor_type, fleet_id)
        self.fields = fields  # Numeric measurements (temperature, voltage, speed)
        self.timestamp = timestamp

    @classmethod
    def from_enriched_data(cls, enriched: EnrichedTelemetry) -> 'TimeSeriesTelemetry':
        """Convert enriched telemetry to time-series format"""
        # Primary measurement for sensor data
        sensor_measurement = cls(
            measurement="vehicle_sensors",
            tags={
                'vehicle_id': enriched.vehicle_id,
                'vehicle_type': enriched.vehicle_info.get('type', 'unknown'),
                'fleet_id': enriched.vehicle_info.get('fleet_id', 'unknown'),
                'location_region': enriched.vehicle_info.get('region', 'unknown')
            },
            fields=enriched.sensor_readings,
            timestamp=enriched.timestamp
        )

        return sensor_measurement

    def to_influx_format(self) -> str:
        """Convert to InfluxDB line protocol format"""
        # measurement,tag1=value1,tag2=value2 field1=1.0,field2=2.0 timestamp
        tags_str = ','.join(f'{k}={v}' for k, v in self.tags.items())
        fields_str = ','.join(f'{k}={v}' for k, v in self.fields.items() if isinstance(v, (int, float)))

        timestamp_ns = int(self.timestamp.timestamp() * 1_000_000_000)

        return f"{self.measurement},{tags_str} {fields_str} {timestamp_ns}"

# Additional measurement types for derived data
class DerivedMetricsMeasurement(TimeSeriesTelemetry):
    @classmethod
    def from_enriched_data(cls, enriched: EnrichedTelemetry) -> 'DerivedMetricsMeasurement':
        return cls(
            measurement="derived_metrics",
            tags={
                'vehicle_id': enriched.vehicle_id,
                'metric_category': 'efficiency'
            },
            fields=enriched.derived_metrics,
            timestamp=enriched.timestamp
        )

class EnvironmentalMeasurement(TimeSeriesTelemetry):
    @classmethod
    def from_enriched_data(cls, enriched: EnrichedTelemetry) -> 'EnvironmentalMeasurement':
        return cls(
            measurement="environmental_data",
            tags={
                'vehicle_id': enriched.vehicle_id,
                'location': enriched.vehicle_info.get('location', 'unknown')
            },
            fields=enriched.environmental_data,
            timestamp=enriched.timestamp
        )
```

## 8.2 InfluxDB and Time Series

### InfluxDB: Optimizing Time-Series Data Storage

InfluxDB represents the specialized database designed specifically for time-series data, offering performance characteristics that traditional relational databases cannot match for temporal workloads.

#### InfluxDB Schema Design

##### **Database Organization**
```sql
-- InfluxDB database and retention policy setup
CREATE DATABASE openvehiclecontrol

-- Retention policies for different data granularities
CREATE RETENTION POLICY "raw_data" ON "openvehiclecontrol" DURATION 7d REPLICATION 1
CREATE RETENTION POLICY "hourly_aggregates" ON "openvehiclecontrol" DURATION 90d REPLICATION 1
CREATE RETENTION POLICY "daily_aggregates" ON "openvehiclecontrol" DURATION 2y REPLICATION 1
CREATE RETENTION POLICY "monthly_aggregates" ON "openvehiclecontrol" DURATION 10y REPLICATION 1

-- Continuous queries for automatic aggregation
CREATE CONTINUOUS QUERY "cq_hourly_battery" ON "openvehiclecontrol" BEGIN
  SELECT mean(battery_level) AS battery_level_avg,
         min(battery_level) AS battery_level_min,
         max(battery_level) AS battery_level_max,
         stddev(battery_level) AS battery_level_stddev
  INTO "hourly_aggregates"."hourly_battery"
  FROM "raw_data"."vehicle_sensors"
  GROUP BY time(1h), vehicle_id
END

CREATE CONTINUOUS QUERY "cq_daily_efficiency" ON "openvehiclecontrol" BEGIN
  SELECT mean(energy_efficiency) AS daily_efficiency_avg,
         sum(power_consumption) AS daily_energy_used
  INTO "daily_aggregates"."daily_efficiency"
  FROM "hourly_aggregates"."hourly_battery"
  GROUP BY time(1d), vehicle_id, fleet_id
END
```

#### Data Ingestion Pipeline

##### **High-Performance Data Ingestion**
```python
# InfluxDB data ingestion engine
class InfluxDataIngestionEngine:
    def __init__(self, influx_client, batch_processor, compression_engine):
        self.client = influx_client
        self.batch_processor = batch_processor
        self.compression = compression_engine
        self.ingestion_buffer = defaultdict(list)
        self.buffer_size_limit = 1000
        self.flush_interval = 30  # seconds

    async def start_ingestion_pipeline(self):
        """Start the data ingestion pipeline"""
        # Start periodic buffer flushing
        asyncio.create_task(self._periodic_buffer_flush())

        # Start ingestion workers
        workers = []
        for i in range(4):  # 4 parallel ingestion workers
            worker = asyncio.create_task(self._ingestion_worker(i))
            workers.append(worker)

        await asyncio.gather(*workers)

    async def ingest_telemetry_data(self, telemetry_data: TimeSeriesTelemetry):
        """Ingest telemetry data with buffering and batching"""
        # Add to buffer
        key = f"{telemetry_data.measurement}_{telemetry_data.tags.get('vehicle_id', 'unknown')}"
        self.ingestion_buffer[key].append(telemetry_data)

        # Check buffer size limits
        if len(self.ingestion_buffer[key]) >= self.buffer_size_limit:
            await self._flush_buffer(key)

    async def _flush_buffer(self, buffer_key: str):
        """Flush buffer to InfluxDB"""
        if not self.ingestion_buffer[buffer_key]:
            return

        data_points = self.ingestion_buffer[buffer_key]
        self.ingestion_buffer[buffer_key] = []

        try:
            # Convert to line protocol format
            lines = [point.to_influx_format() for point in data_points]

            # Compress if beneficial
            if len(lines) > 10:
                compressed_data = await self.compression.compress_lines(lines)
                await self.client.write_compressed(compressed_data)
            else:
                await self.client.write_lines(lines)

            # Update ingestion metrics
            await self._update_ingestion_metrics(len(data_points), buffer_key)

        except Exception as e:
            # Re-queue failed data points
            self.ingestion_buffer[buffer_key].extend(data_points)
            await self._handle_ingestion_error(e, buffer_key)

    async def _periodic_buffer_flush(self):
        """Periodically flush all buffers"""
        while True:
            await asyncio.sleep(self.flush_interval)

            # Flush all buffers
            flush_tasks = []
            for buffer_key in list(self.ingestion_buffer.keys()):
                if self.ingestion_buffer[buffer_key]:
                    task = asyncio.create_task(self._flush_buffer(buffer_key))
                    flush_tasks.append(task)

            if flush_tasks:
                await asyncio.gather(*flush_tasks, return_exceptions=True)

    async def _ingestion_worker(self, worker_id: int):
        """Background ingestion worker"""
        while True:
            try:
                # Get batch from processor
                batch = await self.batch_processor.get_batch()

                if not batch:
                    await asyncio.sleep(0.1)
                    continue

                # Process batch
                await self._process_batch(batch, worker_id)

            except Exception as e:
                await self._handle_worker_error(e, worker_id)

    async def _process_batch(self, batch: list, worker_id: int):
        """Process a batch of telemetry data"""
        # Group by measurement for efficient writing
        measurements = defaultdict(list)

        for telemetry in batch:
            key = telemetry.measurement
            measurements[key].append(telemetry)

        # Write each measurement group
        write_tasks = []
        for measurement, data_points in measurements.items():
            task = self._write_measurement_batch(measurement, data_points)
            write_tasks.append(task)

        await asyncio.gather(*write_tasks)

    async def _write_measurement_batch(self, measurement: str, data_points: list):
        """Write a batch of data points for a specific measurement"""
        lines = [point.to_influx_format() for point in data_points]

        # Use InfluxDB batch write API
        await self.client.write_batch(measurement, lines)

        # Update performance metrics
        await self._update_batch_metrics(measurement, len(data_points))
```

#### Query Optimization Strategies

##### **Time-Series Query Patterns**
```python
# Optimized InfluxDB query patterns
class InfluxQueryOptimizer:
    def __init__(self, influx_client, query_cache, performance_monitor):
        self.client = influx_client
        self.cache = query_cache
        self.monitor = performance_monitor

    async def query_vehicle_telemetry(self, vehicle_id: str, metric: str,
                                    time_range: tuple, aggregation: str = None) -> list:
        """Query vehicle telemetry with optimization"""
        # Check cache first
        cache_key = f"vehicle_{vehicle_id}_{metric}_{time_range}_{aggregation}"
        cached_result = await self.cache.get(cache_key)

        if cached_result:
            return cached_result

        # Build optimized query
        query = await self._build_optimized_query(vehicle_id, metric, time_range, aggregation)

        # Execute query with monitoring
        start_time = time.time()
        result = await self.client.query(query)
        query_time = time.time() - start_time

        # Monitor performance
        await self.monitor.record_query_performance(query, query_time)

        # Cache result if appropriate
        if query_time < 1.0:  # Only cache fast queries
            await self.cache.set(cache_key, result, ttl=300)  # 5 minute cache

        return result

    async def _build_optimized_query(self, vehicle_id: str, metric: str,
                                    time_range: tuple, aggregation: str) -> str:
        """Build optimized InfluxDB query"""
        start_time, end_time = time_range

        # Use appropriate retention policy based on time range
        retention_policy = self._select_retention_policy(start_time, end_time)

        # Build query with optimizations
        base_query = f'''
        SELECT {self._build_select_clause(metric, aggregation)}
        FROM "{retention_policy}"."vehicle_sensors"
        WHERE vehicle_id = '{vehicle_id}'
        AND time >= '{start_time.isoformat()}Z'
        AND time <= '{end_time.isoformat()}Z"
        '''

        # Add aggregation if specified
        if aggregation:
            time_bucket = self._calculate_time_bucket(start_time, end_time)
            base_query += f" GROUP BY time({time_bucket})"

        # Add LIMIT for performance
        base_query += " LIMIT 10000"

        return base_query

    def _select_retention_policy(self, start_time: datetime, end_time: datetime) -> str:
        """Select appropriate retention policy based on query time range"""
        time_span = end_time - start_time

        if time_span.days <= 7:
            return "raw_data"
        elif time_span.days <= 90:
            return "hourly_aggregates"
        elif time_span.days <= 730:  # 2 years
            return "daily_aggregates"
        else:
            return "monthly_aggregates"

    def _build_select_clause(self, metric: str, aggregation: str) -> str:
        """Build optimized SELECT clause"""
        if aggregation:
            return f"{aggregation}({metric}) AS {metric}_{aggregation}"
        else:
            return metric

    def _calculate_time_bucket(self, start_time: datetime, end_time: datetime) -> str:
        """Calculate appropriate time bucket for aggregation"""
        time_span = end_time - start_time

        if time_span.days <= 1:
            return "1m"  # 1 minute
        elif time_span.days <= 7:
            return "1h"  # 1 hour
        elif time_span.days <= 30:
            return "1d"  # 1 day
        else:
            return "7d"  # 1 week
```

## 8.3 Grafana Dashboards

### Grafana: Visual Analytics for Operational Intelligence

Grafana transforms raw time-series data into interactive, real-time dashboards that enable operators to monitor fleet performance, identify issues, and make data-driven decisions.

#### Dashboard Architecture

##### **Multi-Level Dashboard Hierarchy**
```
Executive Dashboard (Fleet Overview)
├── Fleet Performance Dashboard
│   ├── Vehicle Status Dashboard
│   │   ├── Individual Vehicle Dashboard
│   │   │   ├── System-Specific Dashboards
│   │   │   │   ├── Battery Management Dashboard
│   │   │   │   ├── Motor Control Dashboard
│   │   │   │   └── Thermal Management Dashboard
│   │   └── Comparative Analysis Dashboard
│   └── Fleet Analytics Dashboard
└── Operational Dashboard
```

**Implementation:**
```json
// Grafana dashboard configuration (simplified)
{
  "dashboard": {
    "title": "Fleet Overview Dashboard",
    "tags": ["fleet", "overview", "real-time"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Fleet Status Summary",
        "type": "stat",
        "targets": [
          {
            "query": "SELECT count(*) FROM vehicle_status WHERE status = 'active' AND time > now() - 5m",
            "refId": "A"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "mappings": [
              {
                "options": {
                  "match": "null",
                  "result": {
                    "text": "0"
                  }
                },
                "type": "special"
              }
            ]
          }
        }
      },
      {
        "title": "Battery Levels Distribution",
        "type": "histogram",
        "targets": [
          {
            "query": "SELECT battery_level FROM vehicle_sensors WHERE time > now() - 1h GROUP BY vehicle_id",
            "refId": "A"
          }
        ]
      },
      {
        "title": "Energy Consumption Trends",
        "type": "graph",
        "targets": [
          {
            "query": "SELECT mean(power_consumption) FROM derived_metrics WHERE time > now() - 24h GROUP BY time(1h), fleet_id",
            "refId": "A"
          }
        ],
        "seriesOverrides": [
          {
            "alias": "/.*avg/",
            "yaxis": 1
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

#### Real-Time Dashboard Components

##### **Live Data Visualization**
```python
# Real-time dashboard data provider
class GrafanaDataProvider:
    def __init__(self, influx_client, grafana_api, websocket_manager):
        self.influx = influx_client
        self.grafana = grafana_api
        self.websocket = websocket_manager

    async def provide_real_time_data(self, dashboard_id: str, panel_id: str):
        """Provide real-time data updates for Grafana panels"""
        # Subscribe to relevant data streams
        data_subscription = await self._subscribe_to_panel_data(panel_id)

        # Setup WebSocket connection for live updates
        async def data_stream():
            async for data_update in data_subscription:
                # Format for Grafana
                grafana_message = self._format_for_grafana(data_update)

                # Send via WebSocket
                await self.websocket.broadcast_to_dashboard(
                    dashboard_id,
                    panel_id,
                    grafana_message
                )

        # Start streaming
        await data_stream()

    async def _subscribe_to_panel_data(self, panel_id: str):
        """Subscribe to data streams for specific panel"""
        # Get panel configuration
        panel_config = await self.grafana.get_panel_configuration(panel_id)

        # Extract queries from panel
        queries = self._extract_queries_from_panel(panel_config)

        # Create subscriptions for each query
        subscriptions = []
        for query in queries:
            subscription = await self.influx.subscribe_to_query(query)
            subscriptions.append(subscription)

        # Merge subscriptions into single stream
        return self._merge_data_streams(subscriptions)

    def _extract_queries_from_panel(self, panel_config: dict) -> list:
        """Extract InfluxDB queries from Grafana panel configuration"""
        queries = []

        for target in panel_config.get('targets', []):
            if target.get('query'):
                queries.append(target['query'])

        return queries

    async def _merge_data_streams(self, subscriptions: list):
        """Merge multiple data subscriptions into single stream"""
        async def merged_stream():
            while True:
                # Collect updates from all subscriptions
                updates = []
                for subscription in subscriptions:
                    try:
                        update = await asyncio.wait_for(
                            subscription.get(),
                            timeout=0.1
                        )
                        updates.append(update)
                    except asyncio.TimeoutError:
                        continue

                if updates:
                    # Merge and yield combined update
                    merged_update = self._merge_updates(updates)
                    yield merged_update

                await asyncio.sleep(0.1)  # Prevent busy waiting

        return merged_stream()

    def _format_for_grafana(self, data_update: dict) -> dict:
        """Format data update for Grafana consumption"""
        return {
            "data": [
                {
                    "target": data_update.get("target", "value"),
                    "datapoints": [
                        [
                            data_update["value"],
                            data_update["timestamp"] * 1000  # Convert to milliseconds
                        ]
                    ]
                }
            ]
        }
```

#### Custom Dashboard Panels

##### **Vehicle-Centric Visualizations**
```javascript
// Custom Grafana panel for vehicle status visualization
class VehicleStatusPanel {
  constructor($scope, $injector) {
    this.scope = $scope;
    this.injector = $injector;
  }

  link(scope, elem, attrs, ctrl) {
    this.initVehicleStatusVisualization(elem[0]);
  }

  initVehicleStatusVisualization(container) {
    // Create SVG container
    const svg = d3.select(container)
      .append('svg')
      .attr('width', '100%')
      .attr('height', '100%');

    // Setup real-time data subscription
    this.setupDataSubscription(svg);

    // Initialize vehicle status display
    this.createVehicleStatusDisplay(svg);
  }

  setupDataSubscription(svg) {
    // Connect to WebSocket for real-time updates
    const ws = new WebSocket('/ws/vehicle-status');

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.updateVehicleStatus(svg, data);
    };

    ws.onclose = () => {
      // Reconnect logic
      setTimeout(() => this.setupDataSubscription(svg), 5000);
    };
  }

  createVehicleStatusDisplay(svg) {
    // Create vehicle status grid
    const vehicleGrid = svg.append('g')
      .attr('class', 'vehicle-grid');

    // Add status indicators
    vehicleGrid.selectAll('.vehicle-status')
      .data(this.vehicleData)
      .enter()
      .append('circle')
      .attr('class', 'vehicle-status')
      .attr('cx', d => d.x)
      .attr('cy', d => d.y)
      .attr('r', 10)
      .attr('fill', d => this.getStatusColor(d.status));

    // Add vehicle labels
    vehicleGrid.selectAll('.vehicle-label')
      .data(this.vehicleData)
      .enter()
      .append('text')
      .attr('class', 'vehicle-label')
      .attr('x', d => d.x)
      .attr('y', d => d.y + 25)
      .text(d => d.id)
      .attr('text-anchor', 'middle');
  }

  updateVehicleStatus(svg, newData) {
    // Update status circles with smooth transitions
    svg.selectAll('.vehicle-status')
      .data(newData)
      .transition()
      .duration(500)
      .attr('fill', d => this.getStatusColor(d.status));

    // Update battery level indicators
    svg.selectAll('.battery-indicator')
      .data(newData)
      .transition()
      .duration(500)
      .attr('width', d => (d.battery_level / 100) * 20);
  }

  getStatusColor(status) {
    const colorMap = {
      'active': '#10b981',      // Green
      'charging': '#3b82f6',    // Blue
      'maintenance': '#f59e0b', // Yellow
      'offline': '#ef4444',     // Red
      'unknown': '#6b7280'      // Gray
    };
    return colorMap[status] || colorMap['unknown'];
  }
}

// Register panel with Grafana
export { VehicleStatusPanel };
```

## 8.4 Anomaly Detection (Simple Machine Learning)

### Anomaly Detection: Identifying the Unexpected

Anomaly detection transforms passive monitoring into proactive maintenance, identifying deviations from normal behavior before they become critical issues.

#### Statistical Anomaly Detection

##### **Time-Series Anomaly Detection Framework**
```python
# Anomaly detection engine
class AnomalyDetectionEngine:
    def __init__(self, statistical_model, machine_learning_model, alerting_engine):
        self.statistical_detector = statistical_model
        self.ml_detector = machine_learning_model
        self.alerting = alerting_engine

    async def detect_anomalies(self, telemetry_stream):
        """Detect anomalies in real-time telemetry stream"""
        async for telemetry_data in telemetry_stream:
            # Multi-layered anomaly detection
            anomalies = await self._run_anomaly_detection(telemetry_data)

            # Filter and prioritize anomalies
            significant_anomalies = await self._filter_significant_anomalies(anomalies)

            # Generate alerts for significant anomalies
            for anomaly in significant_anomalies:
                await self.alerting.generate_alert(anomaly)

            yield significant_anomalies

    async def _run_anomaly_detection(self, data: dict) -> list:
        """Run multiple anomaly detection algorithms"""
        anomalies = []

        # Statistical anomaly detection
        statistical_anomalies = await self.statistical_detector.detect(data)
        anomalies.extend(statistical_anomalies)

        # Machine learning anomaly detection
        ml_anomalies = await self.ml_detector.detect(data)
        anomalies.extend(ml_anomalies)

        # Rule-based anomaly detection
        rule_anomalies = await self._rule_based_detection(data)
        anomalies.extend(rule_anomalies)

        return anomalies

    async def _rule_based_detection(self, data: dict) -> list:
        """Rule-based anomaly detection for known patterns"""
        anomalies = []

        # Battery voltage anomalies
        if 'battery_voltage' in data:
            voltage = data['battery_voltage']
            if voltage < 2.5:  # Critically low voltage
                anomalies.append({
                    'type': 'battery_voltage_critical',
                    'severity': 'critical',
                    'metric': 'battery_voltage',
                    'value': voltage,
                    'threshold': 2.5,
                    'description': 'Battery voltage critically low'
                })
            elif voltage < 3.0:  # Warning level
                anomalies.append({
                    'type': 'battery_voltage_warning',
                    'severity': 'warning',
                    'metric': 'battery_voltage',
                    'value': voltage,
                    'threshold': 3.0,
                    'description': 'Battery voltage below normal range'
                })

        # Temperature anomalies
        if 'motor_temperature' in data:
            temp = data['motor_temperature']
            if temp > 100:  # Critical temperature
                anomalies.append({
                    'type': 'motor_overheat_critical',
                    'severity': 'critical',
                    'metric': 'motor_temperature',
                    'value': temp,
                    'threshold': 100,
                    'description': 'Motor temperature critically high'
                })
            elif temp > 80:  # Warning temperature
                anomalies.append({
                    'type': 'motor_overheat_warning',
                    'severity': 'warning',
                    'metric': 'motor_temperature',
                    'value': temp,
                    'threshold': 80,
                    'description': 'Motor temperature elevated'
                })

        return anomalies

    async def _filter_significant_anomalies(self, anomalies: list) -> list:
        """Filter and prioritize detected anomalies"""
        significant = []

        for anomaly in anomalies:
            # Calculate anomaly score
            score = await self._calculate_anomaly_score(anomaly)

            # Apply significance threshold
            if score >= self._get_significance_threshold(anomaly['severity']):
                anomaly['score'] = score
                significant.append(anomaly)

        # Sort by score (highest first)
        significant.sort(key=lambda x: x['score'], reverse=True)

        return significant

    async def _calculate_anomaly_score(self, anomaly: dict) -> float:
        """Calculate comprehensive anomaly score"""
        base_score = {
            'critical': 100,
            'warning': 50,
            'info': 10
        }.get(anomaly['severity'], 0)

        # Adjust based on metric importance
        metric_weights = {
            'battery_voltage': 1.5,
            'motor_temperature': 1.3,
            'engine_rpm': 1.0,
            'vehicle_speed': 0.8
        }

        metric_multiplier = metric_weights.get(anomaly.get('metric'), 1.0)

        # Adjust based on deviation magnitude
        if 'threshold' in anomaly and 'value' in anomaly:
            deviation = abs(anomaly['value'] - anomaly['threshold'])
            deviation_multiplier = min(deviation / anomaly['threshold'], 2.0)
        else:
            deviation_multiplier = 1.0

        return base_score * metric_multiplier * deviation_multiplier
```

#### Machine Learning Anomaly Detection

##### **Unsupervised Anomaly Detection**
```python
# Machine learning anomaly detection
class MLAnomalyDetector:
    def __init__(self, model_storage, feature_engineer, model_trainer):
        self.storage = model_storage
        self.feature_engineer = feature_engineer
        self.trainer = model_trainer
        self.models = {}

    async def train_models(self, historical_data: dict):
        """Train anomaly detection models for each vehicle type"""
        for vehicle_type, data in historical_data.items():
            # Feature engineering
            features = await self.feature_engineer.extract_features(data)

            # Train isolation forest model
            model = await self.trainer.train_isolation_forest(features)

            # Store trained model
            await self.storage.save_model(f"{vehicle_type}_anomaly_model", model)

            self.models[vehicle_type] = model

    async def detect(self, telemetry_data: dict) -> list:
        """Detect anomalies using trained ML models"""
        anomalies = []

        vehicle_type = telemetry_data.get('vehicle_type', 'unknown')

        if vehicle_type not in self.models:
            # Use generic model or skip
            return anomalies

        model = self.models[vehicle_type]

        # Extract features from current data
        features = await self.feature_engineer.extract_features_from_single(telemetry_data)

        # Predict anomaly score
        anomaly_score = await self._predict_anomaly_score(model, features)

        # Determine if anomalous
        if anomaly_score > self._get_anomaly_threshold(vehicle_type):
            anomalies.append({
                'type': 'ml_anomaly',
                'severity': self._score_to_severity(anomaly_score),
                'score': anomaly_score,
                'description': f'ML-detected anomaly (score: {anomaly_score:.3f})',
                'features': features
            })

        return anomalies

    async def _predict_anomaly_score(self, model, features) -> float:
        """Predict anomaly score using trained model"""
        # For isolation forest, score is based on path length
        # Lower score = more anomalous
        score = model.decision_function([features])[0]

        # Convert to 0-1 scale where 1 is most anomalous
        return 1 - (score + 1) / 2  # Isolation forest scores are in [-1, 1]

    def _score_to_severity(self, score: float) -> str:
        """Convert anomaly score to severity level"""
        if score > 0.8:
            return 'critical'
        elif score > 0.6:
            return 'warning'
        else:
            return 'info'

    def _get_anomaly_threshold(self, vehicle_type: str) -> float:
        """Get anomaly threshold for vehicle type"""
        # These would be tuned based on validation data
        thresholds = {
            'electric_bus': 0.7,
            'delivery_van': 0.65,
            'scooter': 0.6,
            'unknown': 0.75  # More conservative for unknown types
        }

        return thresholds.get(vehicle_type, thresholds['unknown'])
```

#### Feature Engineering for Anomaly Detection

##### **Temporal and Statistical Features**
```python
# Feature engineering for anomaly detection
class FeatureEngineer:
    def __init__(self, time_window_calculator, statistical_calculator):
        self.time_windows = time_window_calculator
        self.stats = statistical_calculator

    async def extract_features_from_single(self, telemetry_data: dict) -> list:
        """Extract features from single telemetry reading"""
        features = []

        # Raw sensor values
        sensor_features = self._extract_sensor_features(telemetry_data)
        features.extend(sensor_features)

        # Derived features
        derived_features = await self._calculate_derived_features(telemetry_data)
        features.extend(derived_features)

        return features

    def _extract_sensor_features(self, data: dict) -> list:
        """Extract basic sensor features"""
        features = []

        # Battery features
        if 'battery_voltage' in data:
            features.append(data['battery_voltage'])
        if 'battery_current' in data:
            features.append(data['battery_current'])
        if 'battery_temperature' in data:
            features.append(data['battery_temperature'])

        # Motor features
        if 'motor_rpm' in data:
            features.append(data['motor_rpm'])
        if 'motor_temperature' in data:
            features.append(data['motor_temperature'])
        if 'motor_torque' in data:
            features.append(data['motor_torque'])

        # Vehicle dynamics
        if 'vehicle_speed' in data:
            features.append(data['vehicle_speed'])
        if 'acceleration' in data:
            features.append(data['acceleration'])

        return features

    async def _calculate_derived_features(self, data: dict) -> list:
        """Calculate derived features for anomaly detection"""
        features = []

        # Power calculations
        if 'battery_voltage' in data and 'battery_current' in data:
            power = data['battery_voltage'] * data['battery_current']
            features.append(power)

            # Power efficiency (simplified)
            if 'vehicle_speed' in data and data['vehicle_speed'] > 0:
                efficiency = data['vehicle_speed'] / max(abs(data['battery_current']), 0.1)
                features.append(efficiency)

        # Thermal gradients
        if 'motor_temperature' in data and 'ambient_temperature' in data:
            thermal_gradient = data['motor_temperature'] - data['ambient_temperature']
            features.append(thermal_gradient)

            # Cooling effectiveness
            if data['motor_temperature'] > 0:
                cooling_ratio = data['ambient_temperature'] / data['motor_temperature']
                features.append(cooling_ratio)

        # Performance ratios
        if 'motor_rpm' in data and 'vehicle_speed' in data and data['vehicle_speed'] > 0:
            rpm_to_speed_ratio = data['motor_rpm'] / data['vehicle_speed']
            features.append(rpm_to_speed_ratio)

        return features

    async def extract_features(self, historical_data: list) -> list:
        """Extract features from historical data for training"""
        features_list = []

        for data_point in historical_data:
            features = await self.extract_features_from_single(data_point)
            features_list.append(features)

        return features_list
```

## 8.5 CSV/JSON Export

### Data Export: Making Data Portable and Accessible

Effective data export capabilities enable integration with external analysis tools, regulatory reporting, and long-term archival.

#### Multi-Format Export Engine

##### **Flexible Export Pipeline**
```python
# Data export engine
class DataExportEngine:
    def __init__(self, data_retrieval_engine, format_handlers, compression_engine):
        self.data_engine = data_retrieval_engine
        self.format_handlers = format_handlers
        self.compression = compression_engine

    async def export_data(self, query: ExportQuery) -> ExportResult:
        """Export data in specified format with optimizations"""
        # Validate export request
        await self._validate_export_request(query)

        # Retrieve data efficiently
        data_stream = await self.data_engine.execute_query_stream(query)

        # Apply preprocessing if needed
        processed_stream = await self._apply_preprocessing(data_stream, query)

        # Format data
        formatted_data = await self._format_data(processed_stream, query.format)

        # Apply compression if beneficial
        if await self._should_compress(query):
            compressed_data = await self.compression.compress_data(
                formatted_data,
                query.compression_method
            )
            formatted_data = compressed_data

        # Generate metadata
        metadata = await self._generate_export_metadata(query, formatted_data)

        return ExportResult(
            data=formatted_data,
            metadata=metadata,
            format=query.format,
            compression=query.compression_method
        )

    async def _validate_export_request(self, query: ExportQuery):
        """Validate export request parameters"""
        # Check data volume limits
        estimated_size = await self._estimate_export_size(query)
        if estimated_size > self.MAX_EXPORT_SIZE:
            raise ExportError(f"Export size {estimated_size} exceeds limit {self.MAX_EXPORT_SIZE}")

        # Check rate limits
        if not await self._check_rate_limits(query.requestor):
            raise ExportError("Rate limit exceeded")

        # Validate format support
        if query.format not in self.format_handlers:
            raise ExportError(f"Unsupported format: {query.format}")

    async def _format_data(self, data_stream, format_type: str):
        """Format data stream according to specified format"""
        handler = self.format_handlers[format_type]

        if format_type == 'csv':
            return await handler.format_as_csv(data_stream)
        elif format_type == 'json':
            return await handler.format_as_json(data_stream)
        elif format_type == 'parquet':
            return await handler.format_as_parquet(data_stream)
        elif format_type == 'xlsx':
            return await handler.format_as_excel(data_stream)

    async def _should_compress(self, query: ExportQuery) -> bool:
        """Determine if compression should be applied"""
        # Compress large exports
        if query.estimated_size > 10 * 1024 * 1024:  # 10MB
            return True

        # Compress certain formats
        if query.format in ['json', 'csv']:
            return True

        return False
```

#### CSV Export Handler

##### **Optimized CSV Generation**
```python
# CSV export handler
class CSVExportHandler:
    def __init__(self, csv_optimizer, encoding_detector):
        self.optimizer = csv_optimizer
        self.encoding = encoding_detector

    async def format_as_csv(self, data_stream) -> bytes:
        """Format data stream as optimized CSV"""
        # Detect optimal encoding
        optimal_encoding = await self.encoding.detect_optimal_encoding(data_stream)

        # Create CSV buffer
        output = io.StringIO()

        # Get sample for column detection
        sample_data = await self._get_sample_data(data_stream)

        # Determine columns
        columns = self._determine_columns(sample_data)

        # Create CSV writer
        writer = csv.DictWriter(
            output,
            fieldnames=columns,
            delimiter=',',
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
            lineterminator='\n'
        )

        # Write header
        writer.writeheader()

        # Reset stream and write data
        data_stream = await self._reset_stream(data_stream)

        async for data_row in data_stream:
            # Format row data
            formatted_row = await self._format_csv_row(data_row, columns)

            # Write row
            writer.writerow(formatted_row)

        # Get CSV content
        csv_content = output.getvalue()
        output.close()

        # Encode with optimal encoding
        return csv_content.encode(optimal_encoding)

    async def _format_csv_row(self, data_row: dict, columns: list) -> dict:
        """Format data row for CSV output"""
        formatted_row = {}

        for column in columns:
            value = data_row.get(column)

            if value is None:
                formatted_row[column] = ''
            elif isinstance(value, datetime):
                # Format timestamps consistently
                formatted_row[column] = value.isoformat()
            elif isinstance(value, (int, float)):
                # Format numbers appropriately
                if isinstance(value, float):
                    formatted_row[column] = f"{value:.6f}".rstrip('0').rstrip('.')
                else:
                    formatted_row[column] = str(value)
            elif isinstance(value, bool):
                formatted_row[column] = '1' if value else '0'
            elif isinstance(value, list):
                # Convert lists to JSON strings
                formatted_row[column] = json.dumps(value)
            elif isinstance(value, dict):
                # Convert dicts to JSON strings
                formatted_row[column] = json.dumps(value)
            else:
                # Convert to string
                formatted_row[column] = str(value)

        return formatted_row

    def _determine_columns(self, sample_data: list) -> list:
        """Determine CSV columns from sample data"""
        all_keys = set()

        for row in sample_data:
            all_keys.update(row.keys())

        # Sort columns for consistency
        return sorted(all_keys)
```

#### JSON Export Handler

##### **Structured JSON Export**
```python
# JSON export handler
class JSONExportHandler:
    def __init__(self, json_optimizer, schema_validator):
        self.optimizer = json_optimizer
        self.validator = schema_validator

    async def format_as_json(self, data_stream) -> bytes:
        """Format data stream as optimized JSON"""
        # Choose export structure
        if await self._should_use_array_format(data_stream):
            return await self._format_as_json_array(data_stream)
        else:
            return await self._format_as_json_object(data_stream)

    async def _format_as_json_array(self, data_stream) -> bytes:
        """Format as JSON array of objects"""
        data_rows = []

        async for data_row in data_stream:
            # Format row data
            formatted_row = await self._format_json_row(data_row)
            data_rows.append(formatted_row)

        # Create JSON structure
        json_data = {
            'data': data_rows,
            'metadata': {
                'format': 'array',
                'count': len(data_rows),
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0'
            }
        }

        # Serialize with optimization
        return await self.optimizer.serialize_json(json_data)

    async def _format_as_json_object(self, data_stream) -> bytes:
        """Format as JSON object with nested structure"""
        json_data = {
            'data': {},
            'metadata': {
                'format': 'object',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0'
            }
        }

        # Group data by appropriate keys
        grouped_data = defaultdict(list)

        async for data_row in data_stream:
            # Determine grouping key (e.g., vehicle_id)
            group_key = self._get_grouping_key(data_row)

            formatted_row = await self._format_json_row(data_row)
            grouped_data[group_key].append(formatted_row)

        json_data['data'] = dict(grouped_data)
        json_data['metadata']['groups'] = len(grouped_data)

        return await self.optimizer.serialize_json(json_data)

    async def _format_json_row(self, data_row: dict) -> dict:
        """Format individual data row for JSON"""
        formatted_row = {}

        for key, value in data_row.items():
            if isinstance(value, datetime):
                formatted_row[key] = value.isoformat()
            elif isinstance(value, (int, float)):
                formatted_row[key] = value
            elif isinstance(value, (list, dict)):
                formatted_row[key] = value
            elif hasattr(value, '__dict__'):
                # Convert objects to dict
                formatted_row[key] = vars(value)
            else:
                formatted_row[key] = str(value)

        return formatted_row

    def _get_grouping_key(self, data_row: dict) -> str:
        """Determine grouping key for object format"""
        # Use vehicle_id as primary grouping key
        return data_row.get('vehicle_id', 'unknown')

    async def _should_use_array_format(self, data_stream) -> bool:
        """Determine if array format is appropriate"""
        # Use array format for simple exports
        # Use object format for complex hierarchical data
        sample_size = 0
        max_sample = 10

        async for _ in data_stream:
            sample_size += 1
            if sample_size >= max_sample:
                break

        # Reset stream for actual processing
        data_stream = await self._reset_stream(data_stream)

        # Use array for smaller datasets
        return sample_size < max_sample
```

## 8.6 Performance Analysis and Eco-Driving

### Performance Analytics: Optimizing Fleet Efficiency

Performance analysis transforms operational data into actionable insights for improving fleet efficiency, safety, and sustainability.

#### Eco-Driving Analysis Engine

##### **Driving Behavior Analytics**
```python
# Eco-driving analysis engine
class EcoDrivingAnalyzer:
    def __init__(self, telemetry_processor, scoring_engine, recommendations_engine):
        self.telemetry = telemetry_processor
        self.scoring = scoring_engine
        self.recommendations = recommendations_engine

    async def analyze_driving_behavior(self, vehicle_id: str, time_range: tuple) -> EcoDrivingReport:
        """Analyze driving behavior for eco-driving insights"""
        # Retrieve driving data
        driving_data = await self.telemetry.get_driving_data(vehicle_id, time_range)

        # Analyze acceleration patterns
        acceleration_analysis = await self._analyze_acceleration_patterns(driving_data)

        # Analyze braking patterns
        braking_analysis = await self._analyze_braking_patterns(driving_data)

        # Analyze speed consistency
        speed_analysis = await self._analyze_speed_consistency(driving_data)

        # Analyze idling behavior
        idling_analysis = await self._analyze_idling_behavior(driving_data)

        # Calculate eco-driving score
        overall_score = await self.scoring.calculate_overall_score({
            'acceleration': acceleration_analysis,
            'braking': braking_analysis,
            'speed': speed_analysis,
            'idling': idling_analysis
        })

        # Generate recommendations
        recommendations = await self.recommendations.generate_recommendations(
            overall_score,
            acceleration_analysis,
            braking_analysis,
            speed_analysis,
            idling_analysis
        )

        return EcoDrivingReport(
            vehicle_id=vehicle_id,
            time_range=time_range,
            overall_score=overall_score,
            acceleration_analysis=acceleration_analysis,
            braking_analysis=braking_analysis,
            speed_analysis=speed_analysis,
            idling_analysis=idling_analysis,
            recommendations=recommendations,
            generated_at=datetime.utcnow()
        )

    async def _analyze_acceleration_patterns(self, driving_data: list) -> dict:
        """Analyze acceleration behavior"""
        accelerations = []

        for i in range(1, len(driving_data)):
            prev_point = driving_data[i-1]
            curr_point = driving_data[i]

            if 'speed' in prev_point and 'speed' in curr_point and 'timestamp' in prev_point:
                time_diff = (curr_point['timestamp'] - prev_point['timestamp']).total_seconds()
                if time_diff > 0:
                    speed_change = curr_point['speed'] - prev_point['speed']
                    acceleration = speed_change / time_diff  # m/s²

                    accelerations.append({
                        'acceleration': acceleration,
                        'timestamp': curr_point['timestamp'],
                        'speed_before': prev_point['speed'],
                        'speed_after': curr_point['speed']
                    })

        # Analyze acceleration patterns
        analysis = {
            'total_accelerations': len(accelerations),
            'harsh_accelerations': len([a for a in accelerations if a['acceleration'] > 2.5]),  # > 2.5 m/s²
            'smooth_accelerations': len([a for a in accelerations if 0 < a['acceleration'] <= 1.5]),
            'average_acceleration': sum(a['acceleration'] for a in accelerations) / len(accelerations) if accelerations else 0,
            'max_acceleration': max((a['acceleration'] for a in accelerations), default=0),
            'efficiency_score': await self._calculate_acceleration_efficiency(accelerations)
        }

        return analysis

    async def _calculate_acceleration_efficiency(self, accelerations: list) -> float:
        """Calculate acceleration efficiency score (0-100)"""
        if not accelerations:
            return 100  # Perfect score for no data (conservative)

        # Ideal acceleration range for efficiency
        ideal_range = (0.5, 2.0)  # m/s²

        efficient_accelerations = 0
        total_accelerations = 0

        for acc in accelerations:
            accel = acc['acceleration']
            if accel > 0:  # Only consider positive accelerations
                total_accelerations += 1
                if ideal_range[0] <= accel <= ideal_range[1]:
                    efficient_accelerations += 1

        if total_accelerations == 0:
            return 100

        efficiency_ratio = efficient_accelerations / total_accelerations
        return min(100, efficiency_ratio * 100)

    async def _analyze_braking_patterns(self, driving_data: list) -> dict:
        """Analyze braking behavior"""
        brakings = []

        for i in range(1, len(driving_data)):
            prev_point = driving_data[i-1]
            curr_point = driving_data[i]

            if 'speed' in prev_point and 'speed' in curr_point and 'timestamp' in prev_point:
                time_diff = (curr_point['timestamp'] - prev_point['timestamp']).total_seconds()
                if time_diff > 0:
                    speed_change = curr_point['speed'] - prev_point['speed']
                    deceleration = speed_change / time_diff  # m/s² (negative for braking)

                    if deceleration < -0.1:  # Consider it braking
                        brakings.append({
                            'deceleration': abs(deceleration),
                            'timestamp': curr_point['timestamp'],
                            'speed_before': prev_point['speed'],
                            'speed_after': curr_point['speed']
                        })

        # Analyze braking patterns
        analysis = {
            'total_brakings': len(brakings),
            'harsh_brakings': len([b for b in brakings if b['deceleration'] > 3.0]),  # > 3.0 m/s²
            'smooth_brakings': len([b for b in brakings if 0.1 <= b['deceleration'] <= 2.0]),
            'average_deceleration': sum(b['deceleration'] for b in brakings) / len(brakings) if brakings else 0,
            'max_deceleration': max((b['deceleration'] for b in brakings), default=0),
            'efficiency_score': await self._calculate_braking_efficiency(brakings)
        }

        return analysis

    async def _calculate_braking_efficiency(self, brakings: list) -> float:
        """Calculate braking efficiency score (0-100)"""
        if not brakings:
            return 100

        # Ideal deceleration range for efficiency
        ideal_range = (0.5, 2.5)  # m/s²

        efficient_brakings = 0
        total_brakings = 0

        for braking in brakings:
            decel = braking['deceleration']
            total_brakings += 1
            if ideal_range[0] <= decel <= ideal_range[1]:
                efficient_brakings += 1

        if total_brakings == 0:
            return 100

        efficiency_ratio = efficient_brakings / total_brakings
        return min(100, efficiency_ratio * 100)

    async def _analyze_speed_consistency(self, driving_data: list) -> dict:
        """Analyze speed consistency"""
        if not driving_data:
            return {'efficiency_score': 100}

        speeds = [point.get('speed', 0) for point in driving_data if 'speed' in point]

        if len(speeds) < 2:
            return {'efficiency_score': 100}

        # Calculate speed variance
        avg_speed = sum(speeds) / len(speeds)
        variance = sum((speed - avg_speed) ** 2 for speed in speeds) / len(speeds)
        std_deviation = variance ** 0.5

        # Calculate coefficient of variation
        cv = std_deviation / avg_speed if avg_speed > 0 else 0

        # Speed consistency score (lower CV = more consistent = higher score)
        consistency_score = max(0, 100 - (cv * 100))

        analysis = {
            'average_speed': avg_speed,
            'speed_std_deviation': std_deviation,
            'coefficient_of_variation': cv,
            'speed_range': {
                'min': min(speeds),
                'max': max(speeds)
            },
            'efficiency_score': consistency_score
        }

        return analysis

    async def _analyze_idling_behavior(self, driving_data: list) -> dict:
        """Analyze idling behavior"""
        idling_periods = []
        current_idling_start = None

        for point in driving_data:
            speed = point.get('speed', 0)
            timestamp = point.get('timestamp')

            if speed < 1.0:  # Consider vehicle stopped/idling
                if current_idling_start is None:
                    current_idling_start = timestamp
            else:
                if current_idling_start is not None:
                    # End of idling period
                    idling_duration = (timestamp - current_idling_start).total_seconds()
                    if idling_duration > 60:  # Only count idling > 1 minute
                        idling_periods.append({
                            'start': current_idling_start,
                            'end': timestamp,
                            'duration_seconds': idling_duration
                        })
                    current_idling_start = None

        # Handle ongoing idling at end of data
        if current_idling_start is not None:
            last_timestamp = driving_data[-1].get('timestamp')
            idling_duration = (last_timestamp - current_idling_start).total_seconds()
            if idling_duration > 60:
                idling_periods.append({
                    'start': current_idling_start,
                    'end': last_timestamp,
                    'duration_seconds': idling_duration
                })

        # Calculate idling metrics
        total_idling_time = sum(period['duration_seconds'] for period in idling_periods)
        total_observation_time = (driving_data[-1]['timestamp'] - driving_data[0]['timestamp']).total_seconds()

        idling_percentage = (total_idling_time / total_observation_time) * 100 if total_observation_time > 0 else 0

        # Idling efficiency score (lower idling = higher score)
        idling_score = max(0, 100 - idling_percentage)

        analysis = {
            'total_idling_periods': len(idling_periods),
            'total_idling_time_seconds': total_idling_time,
            'idling_percentage': idling_percentage,
            'longest_idling_period': max((p['duration_seconds'] for p in idling_periods), default=0),
            'efficiency_score': idling_score
        }

        return analysis
```

This comprehensive data analytics framework provides the foundation for intelligent fleet management, enabling operators to optimize performance, reduce costs, and improve sustainability through data-driven insights.
