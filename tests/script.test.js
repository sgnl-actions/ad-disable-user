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
      BASIC_USERNAME: 'CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com',
      BASIC_PASSWORD: 'test-password'
    }
  };

  const defaultParams = {
    userDN: 'CN=John Doe,OU=Users,DC=corp,DC=example,DC=com'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    global.console.log = jest.fn();
    global.console.error = jest.fn();
    getBaseURL.mockReturnValue('ldaps://ad.corp.example.com:636');
    mockBind.mockResolvedValue(undefined);
    mockUnbind.mockResolvedValue(undefined);
    mockModify.mockResolvedValue(undefined);
    // Default: enabled user (UAC 512 = NORMAL_ACCOUNT)
    mockSearch.mockResolvedValue({
      searchEntries: [{ dn: defaultParams.userDN, userAccountControl: '512' }]
    });
  });

  describe('invoke handler', () => {
    test('should successfully disable an enabled user (UAC 512 -> 514)', async () => {
      const result = await script.invoke(defaultParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.userDN).toBe(defaultParams.userDN);
      expect(result.disabled).toBe(true);
      expect(result.previousUAC).toBe(512);
      expect(result.newUAC).toBe(514);
      expect(result.address).toBe('ldaps://ad.corp.example.com:636');

      // Verify Client was constructed with correct URL
      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://ad.corp.example.com:636',
        tlsOptions: {}
      });

      // Verify bind was called with correct credentials
      expect(mockBind).toHaveBeenCalledWith(
        'CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com',
        'test-password'
      );

      // Verify search was called for the user DN
      expect(mockSearch).toHaveBeenCalledWith(defaultParams.userDN, {
        scope: 'base',
        attributes: ['userAccountControl'],
        filter: '(objectClass=*)'
      });

      // Verify modify was called to set the ACCOUNTDISABLE bit
      expect(mockModify).toHaveBeenCalledWith(
        defaultParams.userDN,
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
      mockSearch.mockResolvedValue({
        searchEntries: [{ dn: defaultParams.userDN, userAccountControl: '514' }]
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
      mockSearch.mockResolvedValue({
        searchEntries: [{ dn: defaultParams.userDN, userAccountControl: '66048' }]
      });

      const result = await script.invoke(defaultParams, mockContext);

      expect(result.disabled).toBe(true);
      expect(result.previousUAC).toBe(66048);
      expect(result.newUAC).toBe(66050);

      expect(mockModify).toHaveBeenCalledWith(
        defaultParams.userDN,
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

    test('should throw when user is not found (empty search results)', async () => {
      mockSearch.mockResolvedValue({ searchEntries: [] });

      await expect(script.invoke(defaultParams, mockContext)).rejects.toThrow(
        `User not found: ${defaultParams.userDN}`
      );

      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw when userAccountControl is unparseable', async () => {
      mockSearch.mockResolvedValue({
        searchEntries: [{ dn: defaultParams.userDN, userAccountControl: 'not-a-number' }]
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

    test('should throw when BASIC_USERNAME is missing', async () => {
      const contextMissingUsername = {
        ...mockContext,
        secrets: {
          BASIC_PASSWORD: 'test-password'
        }
      };

      await expect(script.invoke(defaultParams, contextMissingUsername)).rejects.toThrow(
        'Missing LDAP bind credentials'
      );
    });

    test('should throw when BASIC_PASSWORD is missing', async () => {
      const contextMissingPassword = {
        ...mockContext,
        secrets: {
          BASIC_USERNAME: 'CN=svc-sgnl,OU=Service Accounts,DC=corp,DC=example,DC=com'
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
        tlsOptions: { rejectUnauthorized: false }
      });
    });

    test('should not set rejectUnauthorized when TLS_SKIP_VERIFY is not set', async () => {
      await script.invoke(defaultParams, mockContext);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://ad.corp.example.com:636',
        tlsOptions: {}
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
  });

  describe('error handler', () => {
    test('should re-throw error and log context', async () => {
      const errorObj = new Error('LDAP connection refused');
      const params = {
        ...defaultParams,
        error: errorObj
      };

      await expect(script.error(params, mockContext)).rejects.toThrow(errorObj);
      expect(console.error).toHaveBeenCalledWith(
        `Disable user failed for ${defaultParams.userDN}: LDAP connection refused`
      );
    });

    test('should re-throw any error type', async () => {
      const errorObj = new Error('Insufficient access rights');
      const params = {
        ...defaultParams,
        error: errorObj
      };

      await expect(script.error(params, mockContext)).rejects.toThrow(errorObj);
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
      expect(result.userDN).toBe(defaultParams.userDN);
      expect(result.reason).toBe('timeout');
      expect(result.halted_at).toBeDefined();
    });

    test('should handle halt without userDN', async () => {
      const params = {
        reason: 'system_shutdown'
      };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.userDN).toBe('unknown');
      expect(result.reason).toBe('system_shutdown');
    });
  });
});
