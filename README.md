# Active Directory Disable User Action

This action disables an enabled user account in on-premise Active Directory using LDAP/LDAPS.

## Overview

The AD Disable User action disables Active Directory accounts by setting the `ACCOUNTDISABLE` bit (0x0002) in the `userAccountControl` attribute. It first looks up the user by their `sAMAccountName`, then reads the current UAC value, checks if the account is enabled, and if so sets the disable bit while preserving all other flags. The action supports comprehensive error handling through the enhanced SGNL testing framework.

Key capabilities:
- **User lookup by sAMAccountName**: Searches the base DN to resolve the user's Distinguished Name
- **Idempotent operations**: Returns success without changes if the account is already disabled
- **UAC bit preservation**: Sets only the ACCOUNTDISABLE bit (0x0002) while preserving all other flags
- **Dry run mode**: Validate parameters without making changes to Active Directory
- **LDAP filter escaping**: Prevents injection via special characters in sAMAccountName
- **Comprehensive testing**: Scenario-based testing framework with full ldapts mocking and 8 test scenarios

## Prerequisites

- On-premise Active Directory domain controller accessible via LDAP or LDAPS
- A service account with permissions to:
  - Search for users in the specified base DN
  - Modify the `userAccountControl` attribute on target user objects
- Network connectivity from the execution environment to the LDAP server

## Configuration

### Authentication

This action uses LDAP Simple Bind authentication with a service account.

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `LDAP_BIND_DN` | Secret | Yes | Bind DN of the service account (e.g., `CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com`) |
| `LDAP_BIND_PASSWORD` | Secret | Yes | Password for the service account |

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `ADDRESS` | Yes | LDAP server URL | `ldaps://ad.corp.example.com:636` |

### Input Parameters

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `baseDN` | string | Yes | Base DN to search for the user | `DC=corp,DC=example,DC=com` |
| `samAccountName` | string | Yes | The user's sAMAccountName (pre-Windows 2000 logon name) | `jdoe` |
| `address` | string | No | Optional LDAP server URL override | `ldaps://ad.corp.example.com:636` |

### Output Structure

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Operation result (success, failed, etc.) |
| `userDN` | string | The resolved Distinguished Name of the user |
| `disabled` | boolean | Whether the user was newly disabled (false if already disabled) |
| `previousUAC` | number | The `userAccountControl` value before the operation |
| `newUAC` | number | The `userAccountControl` value after the operation |
| `address` | string | The LDAP server URL that was used |

## Usage Examples

### Basic Usage

```json
{
  "baseDN": "DC=corp,DC=example,DC=com",
  "samAccountName": "jdoe"
}
```

### Job Specification

```json
{
  "id": "disable-user-account",
  "type": "nodejs-22",
  "script": {
    "repository": "github.com/sgnl-actions/ad-disable-user",
    "version": "v1.0.0",
    "type": "nodejs"
  },
  "script_inputs": {
    "baseDN": "DC=corp,DC=example,DC=com",
    "samAccountName": "jdoe"
  },
  "environment": {
    "ADDRESS": "ldaps://ad.corp.example.com:636"
  },
  "secrets": {
    "LDAP_BIND_DN": "CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com",
    "LDAP_BIND_PASSWORD": "your-service-account-password"
  }
}
```

### With TLS Skip Verify

For environments with self-signed certificates:

```json
{
  "id": "disable-user-account",
  "type": "nodejs-22",
  "script": {
    "repository": "github.com/sgnl-actions/ad-disable-user",
    "version": "v1.0.0",
    "type": "nodejs"
  },
  "script_inputs": {
    "baseDN": "DC=corp,DC=example,DC=com",
    "samAccountName": "jdoe",
    "tlsSkipVerify": true
  },
  "environment": {
    "ADDRESS": "ldaps://ad.corp.example.com:636"
  },
  "secrets": {
    "LDAP_BIND_DN": "CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com",
    "LDAP_BIND_PASSWORD": "your-service-account-password"
  }
}
```

## API Details

This action performs the following LDAP operations:

1. **SEARCH** the base DN to find the user by `sAMAccountName` and get their Distinguished Name
2. **SEARCH** the user DN (base scope) to read the current `userAccountControl` value
3. **MODIFY** the `userAccountControl` attribute with the `ACCOUNTDISABLE` bit set (if it was not already set)

```
SEARCH baseDN (scope=sub, filter=(&(objectClass=user)(sAMAccountName=<samAccountName>)))
SEARCH userDN (scope=base, attrs=userAccountControl)
MODIFY userDN
  REPLACE userAccountControl: <value with bit 0x0002 set>
```

The connection lifecycle is stateless: each invocation binds to the LDAP server, performs the search/modify operations, and unbinds in a `finally` block.

## Error Handling

### Success Scenarios

- **User was enabled**: Account disabled successfully (`disabled: true`, UAC updated)
- **User already disabled**: No changes made (`disabled: false`, UAC unchanged)

### Retryable Errors

| Error | Description |
|-------|-------------|
| Network timeout | Domain Controller unreachable |
| Connection refused | LDAP service not running |
| Server busy | DC under heavy load |

### Fatal Errors

| Error | Description |
|-------|-------------|
| Invalid Credentials | Bind DN or password is incorrect |
| Insufficient Access Rights | Service account lacks permission to search or modify |
| User not found with sAMAccountName | No user exists with the specified sAMAccountName |
| Multiple users found | More than one user matches the sAMAccountName (should not happen in a properly configured AD) |
| Invalid DN Syntax | Malformed Distinguished Name |

## Security Considerations

- **Authentication**: Uses LDAP Simple Bind with a dedicated service account
- **Transport Security**: Supports LDAPS (LDAP over TLS) for encrypted connections
- **TLS Verification**: Certificate verification is enabled by default; `tlsSkipVerify` should only be set to true in development or with self-signed certificates
- **Credential Security**: Bind credentials are provided via secrets and are never logged
- **Connection Lifecycle**: Connections are unbound in a `finally` block to prevent resource leaks
- **LDAP Filter Escaping**: Special characters in sAMAccountName are escaped to prevent LDAP injection

## Development

### Setup

```bash
npm install
```

### Run tests

This action uses the enhanced SGNL testing framework with comprehensive LDAP mocking support. All 8 test scenarios validate user disabling, idempotency, error handling, and dry run behavior:

```bash
npm test
```

The test suite includes:
- Successful disabling of an enabled user (UAC 512 -> 514)
- Idempotent behavior when user is already disabled
- User not found handling
- Authentication and permission failure handling
- Dry run validation
- Missing required parameter validation

### Run tests in watch mode

```bash
npm run test:watch
```

### Build

```bash
npm run build
```

### Validate metadata

```bash
npm run validate
```

### Lint

```bash
npm run lint
npm run lint:fix
```

### Local testing

Copy the sample environment file and configure with your AD credentials:

```bash
cp .env.sample .env
```

Then edit `.env` with your actual values:

```
AD_ADDRESS=ldap://your-dc.example.com:389
LDAP_BIND_DN=CN=admin,DC=example,DC=com
LDAP_BIND_PASSWORD=your-password
TLS_SKIP_VERIFY=false  # Used as tlsSkipVerify input parameter

# Test parameters - customize as needed
BASE_DN=DC=corp,DC=example,DC=com
SAM_ACCOUNT_NAME=jdoe
DRY_RUN=false
```

Then run:

```bash
npm run dev
```

## Troubleshooting

### Common Issues

1. **"Missing LDAP bind credentials"**
   - Ensure `LDAP_BIND_DN` and `LDAP_BIND_PASSWORD` are set in secrets
   - Verify the bind DN is a valid Distinguished Name

2. **"No URL specified"**
   - Ensure the `ADDRESS` environment variable is set or `address` is provided in params
   - Verify the URL format (e.g., `ldaps://ad.corp.example.com:636`)

3. **"Invalid credentials"**
   - Verify the service account DN and password are correct
   - Check that the account is not locked or expired in Active Directory

4. **"Insufficient access rights"**
   - Verify the service account has Read permission to search for users
   - Verify the service account has Write permission on the `userAccountControl` attribute
   - Check if there are any deny ACEs blocking the operation

5. **"User not found with sAMAccountName"**
   - Verify the sAMAccountName is correct (case-insensitive in AD)
   - Check that the user exists within the specified baseDN

6. **TLS/SSL connection errors**
   - Verify the LDAP server is accessible on the configured port
   - For LDAPS, ensure the server certificate is trusted or set `tlsSkipVerify: true` in inputs for testing
   - Check that the correct port is used (389 for LDAP, 636 for LDAPS)

### Verifying Account Status

To verify the action worked correctly, you can check the account status using:

```bash
# Using ldapsearch
ldapsearch -H ldaps://ad.corp.example.com:636 \
  -D "CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com" \
  -W -b "DC=corp,DC=example,DC=com" \
  "(sAMAccountName=jdoe)" userAccountControl

# Using PowerShell
Get-ADUser -Identity "jdoe" -Properties Enabled, userAccountControl | Select-Object Name, Enabled, userAccountControl
```

## Support

- [ldapts Documentation](https://github.com/ldapts/ldapts) - LDAP client library used for Active Directory operations
- [SGNL Testing Framework](https://github.com/sgnl-actions/testing) - Enhanced testing with LDAP mocking capabilities
- [Active Directory LDAP Reference](https://docs.microsoft.com/en-us/windows/win32/ad/active-directory-domain-services)
- [SGNL Actions Documentation](https://github.com/sgnl-actions)
