# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a Kong API Gateway setup with custom OIDC (OpenID Connect) authentication plugin and response transformer plugin. It's a containerized solution that integrates Kong Gateway with Keycloak for authentication, running on Podman with containerized services.

## Build and Development Commands

### Building the Kong Image
```bash
podman build -t kong:kong-oidc .
```

### Setting up the Environment
```bash
# Create podman network
podman network create foo

# Start all services (Kong, Keycloak, HTTP mock)
podman play kube pods.yml --net foo

# Shutdown services
podman play kube pods.yml --down
```

### Configuring the Mock Server
```bash
curl -v -X PUT "http://localhost:1080/mockserver/expectation" -d '{
    "httpRequest": {
        "path": "/"
    },
    "httpResponseTemplate": {
        "template": "{ \"statusCode\": 200, \"body\": \"$!request.headers\" }",
        "templateType": "VELOCITY"
    }
}'
```

### Package Management
- Uses LuaRocks for Lua package management
- Custom Kong plugins are built using rockspec files
- Main dependency: lua-resty-openidc ~> 1.8.0

## Architecture

### Kong Plugin Architecture
- **OIDC Plugin** (`plugins/kong/plugins/oidc/`): Custom OpenID Connect implementation with priority 1000
  - `handler.lua`: Main plugin logic for authentication flows
  - `schema.lua`: Configuration schema definition
  - `filter.lua`: Request filtering logic
  - `utils.lua`: Utility functions for credential injection and header management
- **Custom Response Transformer** (`plugins/kong/plugins/custom-response-transformer/`): Lower priority plugin (999) for response modification

### Configuration Files
- `kong.yml`: Declarative Kong configuration with services, routes, and plugins
- `keycloak-client.json`: Keycloak client configuration for OIDC flow
- `pods.yml`: Kubernetes pod configuration for Podman

### Key Components
1. **Front-end Service**: Public-facing endpoint with OIDC authentication
2. **Back-end Service**: Protected resource server with bearer token validation
3. **Traefik**: Acts as reverse proxy for Keycloak
4. **HTTP Mock**: Test backend service

### Authentication Flows
- **Authorization Code Flow**: For interactive user authentication
- **Bearer Token Validation**: For API access with JWT tokens
- **Token Introspection**: Alternative validation method
- **Session Management**: Uses encrypted cookies with configurable secrets

## Key URLs and Endpoints
- Kong Gateway: `http://localhost:8000`
- Kong Admin API: `http://localhost:8001`
- Prometheus metrics: `http://localhost:8001/metrics`
- Keycloak Admin: `http://localhost:8080/admin/master/console`
- Protected resource: `http://localhost:8000/some/path`
- Logout endpoint: `http://localhost:8000/logout`

## Plugin Configuration Patterns
- OIDC configuration uses client credentials from Keycloak
- Cookie-based session storage with encryption
- Configurable header injection for user info, access tokens, and ID tokens
- Support for bearer-only mode for API endpoints
- Flexible filtering for selective authentication

## Development Notes
- The OIDC plugin is a fork of the archived Nokia/revomatico projects. The plugin relies on https://github.com/zmartzone/lua-resty-openidc/blob/v1.8.0/lib/resty/openidc.lua which itself relies on https://github.com/bungle/lua-resty-session/blob/v4.1.3/lib/resty/session.lua.
- Custom improvements include session content control and user-info endpoint optimization
- Comprehensive logging configuration for debugging authentication flows

## Common Issues and Troubleshooting
- Session state errors: Check redirect URI configuration and cookie domain settings
- State mismatch errors: Can occur with parallel authentication attempts
- Token validation: Ensure proper issuer and audience configuration
- Network connectivity: Services communicate through Docker/Podman network 'foo'
