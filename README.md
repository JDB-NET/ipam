<div align="center">
  <img src="https://projects.jdbnet.co.uk/ipam/img/favicon.png" alt="IPAM" width="200" />
  
  # IP Address Management
</div>

A Flask-based web application for comprehensive IP Address Management (IPAM). Manage subnets, IP addresses, devices, DHCP pools, and physical rack infrastructure with an intuitive web interface.

## Features

- **Subnet Management**: Create and manage IP subnets with CIDR notation (supports /24 to /32)
- **IP Address Tracking**: Automatic IP address generation and tracking for each subnet
- **Device Management**: Track devices with types (Server, VM, Switch, Firewall, WiFi AP, Printer, Other)
- **IP Assignment**: Assign IP addresses to devices with automatic hostname updates
- **DHCP Pool Configuration**: Configure DHCP pools with start/end IP ranges and excluded IPs
- **Rack Management**: Physical infrastructure tracking with U positions and front/back sides
- **Site Organization**: Organize subnets and devices by site/location
- **Audit Logging**: Complete audit trail of all changes with user, action, details, and timestamps
- **User Management**: Multi-user support with secure password authentication
- **Role-Based Access Control (RBAC)**: Granular permission system with default roles (admin, user, view_only) and custom role creation
- **REST API**: Full-featured REST API with API key authentication for programmatic access
- **CSV Export**: Export subnet and rack data to CSV files
- **Device Statistics**: View device counts by type
- **Web Interface**: Modern, responsive web GUI built with Tailwind CSS and dark mode support

## Quick Start with Docker

### Docker Run

```bash
docker run -d \
  --name ipam \
  -p 5000:5000 \
  -e MYSQL_HOST=10.10.2.27 \
  -e MYSQL_USER=ipam \
  -e MYSQL_PASSWORD=your_password \
  -e MYSQL_DATABASE=ipam \
  -e SECRET_KEY=your_secret_key \
  -e NAME="Your Organization" \
  -e LOGO_PNG="https://example.com/logo.png" \
  ghcr.io/jdb-net/ipam:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  ipam:
    image: ghcr.io/jdb-net/ipam:latest
    container_name: ipam
    restart: unless-stopped
    ports:
      - "5000:5000"  # Web interface
    environment:
      - MYSQL_HOST=10.10.2.27
      - MYSQL_USER=ipam
      - MYSQL_PASSWORD=your_password
      - MYSQL_DATABASE=ipam
      - SECRET_KEY=your_secret_key
      - NAME=Your Organization
      - LOGO_PNG=https://example.com/logo.png
```

## Configuration

### Environment Variables

- `MYSQL_HOST`: MySQL/MariaDB host (default: localhost)
- `MYSQL_USER`: Database user (default: user)
- `MYSQL_PASSWORD`: Database password (default: password)
- `MYSQL_DATABASE`: Database name (default: ipam)
- `SECRET_KEY`: Flask secret key for sessions (**REQUIRED in production!**)
- `NAME`: Organization name displayed in header (default: JDB-NET)
- `LOGO_PNG`: URL or path to organization logo (default: JDB-NET logo)

### Database Setup

The application automatically initializes the database schema on first run. Ensure the database and user exist with appropriate permissions:

```sql
CREATE DATABASE ipam;
CREATE USER 'ipam'@'%' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON ipam.* TO 'ipam'@'%';
FLUSH PRIVILEGES;
```

## Usage

### First Login

1. Access the web interface at `http://your-server:5000`
2. Log in with the default credentials:
   - Email: `admin@example.com`
   - Password: `password`
3. **Change the default password immediately** via the Users page

### Managing Subnets

1. Navigate to "Admin" from the main menu
2. Click "Add Subnet" and fill in:
   - **Name**: Friendly name for the subnet (e.g., "Office LAN")
   - **CIDR**: Subnet in CIDR notation (e.g., `192.168.1.0/24`)
   - **Site**: Site/location identifier
3. The system automatically generates all IP addresses in the subnet

### Adding Devices

1. Navigate to "Devices" from the main menu
2. Click "Add Device"
3. Enter device name and select device type
4. Click "Create Device"

### Assigning IP Addresses to Devices

1. Open a device from the Devices page
2. Select a subnet and available IP address
3. Click "Assign IP" - the hostname is automatically updated

### Configuring DHCP Pools

1. Open a subnet view
2. Click "Configure DHCP Pool"
3. Set the start and end IP addresses
4. Optionally specify excluded IPs (comma-separated)
5. IPs within the pool range are automatically marked as "DHCP"

### Managing Racks

1. Navigate to "Racks" from the main menu
2. Click "Add Rack" and specify:
   - **Name**: Rack identifier
   - **Site**: Site location
   - **Height**: Rack height in U units
3. Open a rack to assign devices to specific U positions (front or back)

### Audit Log

View all changes and actions in the "Audit Log" section, with filtering by user, subnet, action type, or device name.

### Exporting Data

- **Subnet CSV**: Click "Export CSV" on any subnet page to download IP addresses with hostnames
- **Rack CSV**: Click "Export CSV" on any rack page to download rack layout information

### Role-Based Access Control

The system uses a granular role-based access control (RBAC) system to manage user permissions:

1. **Default Roles**:
   - **Admin**: Full access to all features including user and role management
   - **User**: Can view and manage most features (devices, subnets, racks, etc.) but cannot manage users or roles
   - **View Only**: Read-only access to view pages but cannot make any changes

2. **Custom Roles**: Administrators can create custom roles with specific permission sets from the Users page

3. **Permission Granularity**: Permissions are organized into categories:
   - View permissions (access to pages)
   - Device Management (add, edit, delete devices)
   - Network Management (subnet operations)
   - Rack Management (rack operations)
   - DHCP Configuration
   - Administration (user and role management)

4. **User Management**: Navigate to the Users page to:
   - Create and manage users
   - Assign roles to users
   - Create custom roles with specific permissions
   - View and regenerate API keys

### REST API

The application includes a comprehensive REST API for programmatic access:

1. **Authentication**: All API requests require an API key, which can be provided via:
   - `X-API-Key` header
   - `Authorization: Bearer <api_key>` header
   - `?api_key=<api_key>` query parameter

2. **Base URL**: All API endpoints are prefixed with `/api/v1`

3. **Available Endpoints**:
   - **Devices**: `GET`, `POST`, `PUT`, `DELETE /api/v1/devices`
   - **Subnets**: `GET`, `POST`, `PUT`, `DELETE /api/v1/subnets`
   - **Racks**: `GET`, `POST`, `DELETE /api/v1/racks`
   - **Device Types**: `GET /api/v1/device-types`
   - **DHCP**: `GET`, `POST /api/v1/subnets/{id}/dhcp`
   - **Audit Log**: `GET /api/v1/audit`
   - **Users & Roles**: `GET /api/v1/users`, `GET /api/v1/roles` (admin only)

4. **API Keys**: Each user has a unique API key that can be viewed and regenerated from the Users page. API keys respect the same role-based permissions as the web interface.

5. **Documentation**: Full API documentation is available in the Help page of the web interface.

**Example API Request**:
```bash
curl -H "X-API-Key: your_api_key" \
     https://your-server:5000/api/v1/devices
```

## Kubernetes Deployment

The project includes a Kubernetes deployment manifest. See `deployment.yml` for details.

**Example Kubernetes deployment:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ipam
  namespace: ipam
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: ipam
        image: ghcr.io/jdb-net/ipam:latest
        ports:
        - containerPort: 5000
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: ipam-secrets
              key: secret-key
        - name: MYSQL_HOST
          value: "mysql-service"
        - name: MYSQL_USER
          value: "ipam"
        - name: MYSQL_PASSWORD
          valueFrom:
            secretKeyRef:
              name: ipam-secrets
              key: mysql-password
        - name: MYSQL_DATABASE
          value: "ipam"
```

## Security Notes

- **CHANGE THE DEFAULT ADMIN PASSWORD** immediately after first login
- **CHANGE THE SECRET_KEY** in production - use a strong random string (e.g., `openssl rand -hex 32`)
- Use strong passwords for database access
- Ensure database connections are secured (consider SSL/TLS for MySQL connections)
- Review audit logs regularly for unauthorized changes
- Limit database user permissions if possible (though CREATE/ALTER may be needed for schema initialization)
- **API Keys**: Keep API keys secure and never share them publicly. Regenerate keys if they may have been compromised
- **Role-Based Access**: Use the RBAC system to grant users only the permissions they need (principle of least privilege)
- **HTTPS**: Use HTTPS in production to protect API keys and session data in transit

## Troubleshooting

### Database Connection Issues

- Ensure MySQL/MariaDB is running and accessible from the container
- Check database credentials in environment variables
- Verify database and user exist with proper permissions
- Check network connectivity between container and database
- Ensure the database name matches exactly (case-sensitive on some systems)

### Application Not Starting

- Check container logs: `docker logs ipam`
- Verify all required environment variables are set
- Ensure port 5000 is not already in use
- Check that MySQL/MariaDB is reachable

### Subnet or IP Not Appearing

- Verify CIDR notation is correct (supports /24 to /32)
- Check subnet was created successfully (view in Admin page)
- Ensure you're logged in with appropriate permissions
- Check application logs for errors

### Device IP Assignment Issues

- Verify the IP address is available (not already assigned)
- Check that the IP is not in a DHCP pool range
- Ensure the device exists and is visible in the Devices list

## License

This project is provided as-is for IP Address Management.