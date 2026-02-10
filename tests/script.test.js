import { jest } from '@jest/globals';

// Mock ldapts before importing script
const mockBind = jest.fn();
const mockUnbind = jest.fn();
const mockModify = jest.fn();
const mockSearch = jest.fn();

jest.unstable_mockModule('ldapts', () => ({
  Client: jest.fn().mockImplementation(() => ({
    bind: mockBind,
    unbind: mockUnbind,
    modify: mockModify,
    search: mockSearch
  })),
  Change: jest.fn().mockImplementation((opts) => ({
    operation: opts.operation,
    modification: opts.modification
  })),
  Attribute: jest.fn().mockImplementation((opts) => ({
    [opts.type]: opts.values
  }))
}));

// Mock @sgnl-actions/utils
jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  getBaseURL: jest.fn()
}));

const { Client } = await import('ldapts');
const { getBaseURL } = await import('@sgnl-actions/utils');
const { default: script } = await import('../src/script.mjs');

describe('AD Disable User Script', () => {
  const mockContext = {
    environment: {
      ADDRESS: 'ldaps://ad.corp.example.com:636'
    },
    secrets: {
      LDAP_BIND_DN: 'CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com',
      LDAP_BIND_PASSWORD: 'test-password'
    }
  };

  const defaultParams = {
    baseDN: 'DC=corp,DC=example,DC=com',
    samAccountName: 'jdoe'
  };

  const resolvedUserDN = 'CN=John Doe,OU=Users,DC=corp,DC=example,DC=com';

  beforeEach(() => {
    jest.clearAllMocks();
    global.console.log = jest.fn();
    global.console.error = jest.fn();
    getBaseURL.mockReturnValue('ldaps://ad.corp.example.com:636');
    mockBind.mockResolvedValue(undefined);
    mockUnbind.mockResolvedValue(undefined);
    mockModify.mockResolvedValue(undefined);
    // Default: user lookup returns one user, enabled (UAC 512 = NORMAL_ACCOUNT)
    mockSearch.mockImplementation((baseDN, options) => {
      if (options.filter.includes('sAMAccountName')) {
        // User lookup by sAMAccountName
        return Promise.resolve({
          searchEntries: [{ dn: resolvedUserDN }]
        });
      } else {
        // UAC lookup
        return Promise.resolve({
          searchEntries: [{ dn: resolvedUserDN, userAccountControl: '512' }]
        });
      }
    });
  });

  describe('invoke handler', () => {
    test('should successfully find and disable an enabled user (UAC 512 -> 514)', async () => {
      const result = await script.invoke(defaultParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.userDN).toBe(resolvedUserDN);
      expect(result.disabled).toBe(true);
      expect(result.previousUAC).toBe(512);
      expect(result.newUAC).toBe(514);
      expect(result.address).toBe('ldaps://ad.corp.example.com:636');

      // Verify Client was constructed with correct URL and options
      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://ad.corp.example.com:636',
        timeout: 10000,
        connectTimeout: 10000,
        tlsOptions: { rejectUnauthorized: true }
      });

      // Verify bind was called with correct credentials
      expect(mockBind).toHaveBeenCalledWith(
        'CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com',
        'test-password'
      );

      // Verify search was called for sAMAccountName lookup
      expect(mockSearch).toHaveBeenCalledWith(defaultParams.baseDN, {
        scope: 'sub',
        filter: `(&(objectClass=user)(sAMAccountName=${defaultParams.samAccountName}))`,
        attributes: ['distinguishedName']
      });

      // Verify search was called for UAC lookup
      expect(mockSearch).toHaveBeenCalledWith(resolvedUserDN, {
        scope: 'base',
        attributes: ['userAccountControl'],
        filter: '(objectClass=*)'
      });

      // Verify modify was called to set the ACCOUNTDISABLE bit
      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          {
            operation: 'replace',
            modification: {
              userAccountControl: ['514']
            }
          }
        ]
      );

      // Verify unbind was called
      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should return disabled: false when user is already disabled (UAC 514)', async () => {
      mockSearch.mockImplementation((baseDN, options) => {
        if (options.filter.includes('sAMAccountName')) {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN }]
          });
        } else {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN, userAccountControl: '514' }]
          });
        }
      });

      const result = await script.invoke(defaultParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.disabled).toBe(false);
      expect(result.previousUAC).toBe(514);
      expect(result.newUAC).toBe(514);

      // modify should NOT be called when already disabled
      expect(mockModify).not.toHaveBeenCalled();
      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should preserve other UAC bits (66048 -> 66050)', async () => {
      // 66048 = 65536 (DONT_EXPIRE_PASSWORD) + 512 (NORMAL_ACCOUNT)
      mockSearch.mockImplementation((baseDN, options) => {
        if (options.filter.includes('sAMAccountName')) {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN }]
          });
        } else {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN, userAccountControl: '66048' }]
          });
        }
      });

      const result = await script.invoke(defaultParams, mockContext);

      expect(result.disabled).toBe(true);
      expect(result.previousUAC).toBe(66048);
      expect(result.newUAC).toBe(66050);

      expect(mockModify).toHaveBeenCalledWith(
        resolvedUserDN,
        [
          {
            operation: 'replace',
            modification: {
              userAccountControl: ['66050']
            }
          }
        ]
      );
    });

    test('should throw when user is not found by sAMAccountName', async () => {
      mockSearch.mockImplementation((baseDN, options) => {
        if (options.filter.includes('sAMAccountName')) {
          return Promise.resolve({ searchEntries: [] });
        }
        return Promise.resolve({
          searchEntries: [{ dn: resolvedUserDN, userAccountControl: '512' }]
        });
      });

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow(
        `User not found with sAMAccountName: ${defaultParams.samAccountName}`
      );

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw when multiple users found with same sAMAccountName', async () => {
      mockSearch.mockImplementation((baseDN, options) => {
        if (options.filter.includes('sAMAccountName')) {
          return Promise.resolve({
            searchEntries: [
              { dn: 'CN=User1,OU=Users,DC=corp,DC=example,DC=com' },
              { dn: 'CN=User2,OU=Users,DC=corp,DC=example,DC=com' }
            ]
          });
        }
        return Promise.resolve({
          searchEntries: [{ dn: resolvedUserDN, userAccountControl: '512' }]
        });
      });

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow(
        `Multiple users found with sAMAccountName: ${defaultParams.samAccountName}. Expected exactly one.`
      );

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw when user DN not found during UAC lookup', async () => {
      mockSearch.mockImplementation((baseDN, options) => {
        if (options.filter.includes('sAMAccountName')) {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN }]
          });
        } else {
          return Promise.resolve({ searchEntries: [] });
        }
      });

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow(
        `User not found: ${resolvedUserDN}`
      );

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw when userAccountControl is unparseable', async () => {
      mockSearch.mockImplementation((baseDN, options) => {
        if (options.filter.includes('sAMAccountName')) {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN }]
          });
        } else {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN, userAccountControl: 'not-a-number' }]
          });
        }
      });

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow(
        'Unable to parse userAccountControl value: not-a-number'
      );

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw on LDAP search error', async () => {
      mockSearch.mockRejectedValueOnce(new Error('Search operation failed'));

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow('Search operation failed');

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw on LDAP modify error', async () => {
      mockModify.mockRejectedValueOnce(new Error('Insufficient access rights'));

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow('Insufficient access rights');

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw on bind failure', async () => {
      mockBind.mockRejectedValueOnce(new Error('Invalid credentials'));

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow('Invalid credentials');

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw when LDAP_BIND_DN is missing', async () => {
      const contextMissingUsername = {
        ...mockContext,
        secrets: {
          LDAP_BIND_PASSWORD: 'test-password'
        }
      };

      await expect(script.invoke(defaultParams, contextMissingUsername)).rejects.toThrow(
        'Missing LDAP bind credentials'
      );
    });

    test('should throw when LDAP_BIND_PASSWORD is missing', async () => {
      const contextMissingPassword = {
        ...mockContext,
        secrets: {
          LDAP_BIND_DN: 'CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com'
        }
      };

      await expect(script.invoke(defaultParams, contextMissingPassword)).rejects.toThrow(
        'Missing LDAP bind credentials'
      );
    });

    test('should set TLS rejectUnauthorized to false when TLS_SKIP_VERIFY is true', async () => {
      const contextWithTlsSkip = {
        ...mockContext,
        environment: {
          ...mockContext.environment,
          TLS_SKIP_VERIFY: 'true'
        }
      };

      await script.invoke(defaultParams, contextWithTlsSkip);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://ad.corp.example.com:636',
        timeout: 10000,
        connectTimeout: 10000,
        tlsOptions: { rejectUnauthorized: false }
      });
    });

    test('should set rejectUnauthorized to true for ldaps:// URLs when TLS_SKIP_VERIFY is not set', async () => {
      await script.invoke(defaultParams, mockContext);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://ad.corp.example.com:636',
        timeout: 10000,
        connectTimeout: 10000,
        tlsOptions: { rejectUnauthorized: true }
      });
    });

    test('should not include tlsOptions for ldap:// URLs when TLS_SKIP_VERIFY is not set', async () => {
      getBaseURL.mockReturnValue('ldap://ad.corp.example.com:389');

      await script.invoke(defaultParams, mockContext);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldap://ad.corp.example.com:389',
        timeout: 10000,
        connectTimeout: 10000
      });
    });

    test('should use address from params via getBaseURL', async () => {
      const paramsWithAddress = {
        ...defaultParams,
        address: 'ldaps://custom-ad.corp.example.com:636'
      };
      getBaseURL.mockReturnValue('ldaps://custom-ad.corp.example.com:636');

      const result = await script.invoke(paramsWithAddress, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(paramsWithAddress, mockContext);
      expect(result.address).toBe('ldaps://custom-ad.corp.example.com:636');
    });

    test('should call getBaseURL with params and context', async () => {
      await script.invoke(defaultParams, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(defaultParams, mockContext);
    });

    test('should throw when baseDN is missing', async () => {
      const params = { samAccountName: 'jdoe' };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('baseDN is required');
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should throw when samAccountName is missing', async () => {
      const params = { baseDN: 'DC=corp,DC=example,DC=com' };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('samAccountName is required');
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should handle unbind errors gracefully', async () => {
      mockUnbind.mockRejectedValueOnce(new Error('Unbind failed'));

      const result = await script.invoke(defaultParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.disabled).toBe(true);
    });

    test('should not mask original error when unbind also fails', async () => {
      mockSearch.mockRejectedValueOnce(new Error('Search operation failed'));
      mockUnbind.mockRejectedValueOnce(new Error('Unbind failed'));

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow('Search operation failed');
    });

    test('should return dry_run_completed when dry_run is true', async () => {
      const params = { ...defaultParams, dry_run: true };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('dry_run_completed');
      expect(result.baseDN).toBe(defaultParams.baseDN);
      expect(result.samAccountName).toBe(defaultParams.samAccountName);
      expect(result.userDN).toBe(null);
      expect(result.disabled).toBe(false);
      expect(mockBind).not.toHaveBeenCalled();
      expect(mockSearch).not.toHaveBeenCalled();
    });

    test('should escape special characters in sAMAccountName for LDAP filter', async () => {
      const paramsWithSpecialChars = {
        ...defaultParams,
        samAccountName: 'user*test(name)'
      };

      mockSearch.mockImplementation((baseDN, options) => {
        if (options.filter.includes('sAMAccountName')) {
          // Verify the filter contains escaped characters
          expect(options.filter).toContain('user\\2atest\\28name\\29');
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN }]
          });
        } else {
          return Promise.resolve({
            searchEntries: [{ dn: resolvedUserDN, userAccountControl: '512' }]
          });
        }
      });

      await script.invoke(paramsWithSpecialChars, mockContext);
    });
  });

  describe('error handler', () => {
    test('should re-throw connection errors for framework retry', async () => {
      const errorObj = new Error('LDAP connection refused');
      const params = {
        ...defaultParams,
        error: errorObj
      };

      await expect(script.error(params, mockContext)).rejects.toThrow(errorObj);
    });

    test('should wrap authentication errors', async () => {
      const errorObj = new Error('Invalid credentials');
      const params = {
        ...defaultParams,
        error: errorObj
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('LDAP authentication failed');
    });

    test('should wrap permission errors', async () => {
      const errorObj = new Error('Insufficient access rights');
      const params = {
        ...defaultParams,
        error: errorObj
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('Insufficient LDAP permissions');
    });

    test('should wrap not found errors', async () => {
      const errorObj = new Error('User not found');
      const params = {
        ...defaultParams,
        error: errorObj
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('User not found');
    });

    test('should wrap multiple users found errors', async () => {
      const errorObj = new Error('Multiple users found with sAMAccountName');
      const params = {
        ...defaultParams,
        error: errorObj
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('Multiple users found');
    });
  });

  describe('halt handler', () => {
    test('should handle graceful shutdown with parameters', async () => {
      const params = {
        ...defaultParams,
        reason: 'timeout'
      };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.baseDN).toBe(defaultParams.baseDN);
      expect(result.samAccountName).toBe(defaultParams.samAccountName);
      expect(result.reason).toBe('timeout');
      expect(result.halted_at).toBeDefined();
    });

    test('should handle halt without baseDN and samAccountName', async () => {
      const params = {
        reason: 'system_shutdown'
      };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.baseDN).toBe('unknown');
      expect(result.samAccountName).toBe('unknown');
      expect(result.reason).toBe('system_shutdown');
    });
  });
});
