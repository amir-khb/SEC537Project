# URLScan.io Cyber Intelligence Gathering

## Overview
This project implements a comprehensive system for gathering and analyzing cyber intelligence from URLScan.io, focusing on identifying and monitoring malicious websites, particularly those targeting Turkish government institutions and global organizations.

## Project Structure

### Task 1: Real-time Malicious Data Capture and Parsing

#### Data Collection System
- Utilizes URLScan.io's API endpoint as the primary data source
- Provides comprehensive scan results including URL information, domain data, IP addresses, and metadata
- Features stable API performance with no rate limiting during initial collection phase

#### Technical Implementation

1. **Multi-Process Architecture**
   - Implements Producer-Consumer pattern
   - One URL producer and multiple consumers (default: 3 concurrent processes)
   - Utilizes Python's multiprocessing library
   - Manages shared resources through Queue and Value objects with proper locking

2. **Data Collection Process**
   - Continuous monitoring of URLScan.io's main page using Selenium WebDriver
   - Extracts key metadata:
     - Timestamp of detection
     - Target URL
     - Scan URL
     - Age of scan
     - Page size
     - Number of requests
     - Associated IP addresses
     - Identified threats
     - Access status (public/private)

3. **Robust Error Handling**
   - Comprehensive logging system
   - Automatic retry mechanisms with appropriate delays
   - Protection against duplicate entries using URL filtering

4. **Data Management**
   - Structured JSON storage format
   - Separate storage for general results and verified malicious verdicts
   - Real-time statistics updates
   - Progress monitoring with live backlog tracking

### Defensive Capabilities

#### Anti-Blocking Measures
- Dynamic proxy rotation on detection of blocking
- Multiple user-agent rotation
- Automated session management
- Built-in delays between requests
- Error handling with exponential backoff

#### Proxy Management System
- Robust ProxyHandler class
- Multiple proxy sources:
  - free-proxy-list.net
  - proxyscrape.com
  - geonode.com API
- Multi-threaded proxy validation featuring:
  - Concurrent validation of up to 20 proxies
  - Test connections against major websites
  - Automatic proxy refresh mechanism
  - Maintenance of validated proxy pool

## Performance Optimization

### Multi-Processing Architecture
The system implements a sophisticated multi-process architecture to handle the disparity between URL collection and verdict processing speeds:

1. **Producer-Consumer Pattern**
   - Single Producer Process: Dedicated to URL monitoring and collection
   - Multiple Consumer Processes: Handle verdict processing and analysis
   - Shared Queue System: Manages URL processing backlog
   - Atomic Counter: Tracks processing backlog with thread-safe operations

2. **Benefits**
   - Prevents real-time data loss
   - Balances workload across processes
   - Maximizes system resource utilization
   - Maintains consistent processing flow
   - Enables real-time progress monitoring

### Implementation Details
- Utilizes Python's multiprocessing library
- Implements proper synchronization mechanisms (Queue, Value, Lock)
- Ensures thread-safe operations
- Prevents race conditions in shared backlog counter management

## Results
The implementation successfully:
- Overcomes IP blocking issues
- Maintains continuous scanning capabilities
- Enables comprehensive data collection
- Provides detailed analysis of malicious websites
- Generates regular statistical reports on findings

## Sample Statistics
Based on a 2-hour runtime:
- Total URLs analyzed: 277
- Malicious verdicts: 44 (15.88%)
- Unknown targets: 2 (4.55% of malicious)

### Top Targeted Organizations
1. USPS: 21 instances
2. Fake Shop: 16 instances
3. Telegram: 2 instances
4. Others: Various single instances

### Primary Hosting Providers
1. TENCENT-NET-AP-CN: 19 instances
2. CLOUDFLARENET, US: 10 instances
3. Malakmadze Web LLC, GE: 4 instances
