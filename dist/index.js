// SGNL Job Script - Auto-generated bundle
'use strict';

var ldapts = require('ldapts');

/**
 * SGNL Actions - Authentication Utilities
 *
 * Shared authentication utilities for SGNL actions.
 * Supports: Bearer Token, Basic Auth, OAuth2 Client Credentials, OAuth2 Authorization Code
 */


/**
 * Get the base URL/address for API calls
 * @param {Object} params - Request parameters
 * @param {string} [params.address] - Address from params
 * @param {Object} context - Execution context
 * @returns {string} Base URL
 */
function getBaseURL(params, context) {
  const env = context.environment || {};
  const address = params?.address || env.ADDRESS;

  if (!address) {
    throw new Error('No URL specified. Provide address parameter or ADDRESS environment variable');
  }

  // Remove trailing slash if present
  return address.endsWith('/') ? address.slice(0, -1) : address;
}

/**
 * Active Directory Disable User Action
 *
 * Disables an enabled user account in on-premise Active Directory by setting
 * the ACCOUNTDISABLE bit (0x0002) in the userAccountControl attribute.
 */


/**
 * Helper function to disable a user account in Active Directory
 * @param {string} userDN - Distinguished Name of the user
 * @param {Client} client - Bound ldapts Client instance
 * @returns {Promise<{disabled: boolean, previousUAC: number, newUAC: number}>}
 */
async function disableUser(userDN, client) {
  const { searchEntries } = await client.search(userDN, {
    scope: 'base',
    attributes: ['userAccountControl'],
    filter: '(objectClass=*)'
  });

  if (!searchEntries || searchEntries.length === 0) {
    throw new Error(`User not found: ${userDN}`);
  }

  const rawUAC = searchEntries[0].userAccountControl;
  const uac = parseInt(rawUAC, 10);

  if (isNaN(uac)) {
    throw new Error(`Unable to parse userAccountControl value: ${rawUAC}`);
  }

  // Check if ACCOUNTDISABLE bit (0x0002) is already set
  if ((uac & 2) !== 0) {
    return { disabled: false, previousUAC: uac, newUAC: uac };
  }

  // Set the ACCOUNTDISABLE bit
  const newUAC = uac | 2;

  await client.modify(userDN, [
    {
      operation: 'replace',
      modification: {
        userAccountControl: [newUAC.toString()]
      }
    }
  ]);

  return { disabled: true, previousUAC: uac, newUAC };
}

var script = {
  /**
   * Main execution handler - disables an enabled user in on-premise Active Directory
   * @param {Object} params - Job input parameters
   * @param {string} params.userDN - Distinguished Name of the user to disable
   * @param {string} [params.address] - Optional LDAP server URL override
   * @param {Object} context - Execution context with env, secrets, outputs
   * @param {string} context.environment.ADDRESS - Default LDAP server URL
   * @param {string} context.secrets.LDAP_BIND_DN - Bind DN for LDAP authentication
   * @param {string} context.secrets.LDAP_BIND_PASSWORD - Bind password for LDAP authentication
   * @param {string} [context.environment.TLS_SKIP_VERIFY] - Set to 'true' to skip TLS certificate verification
   * @returns {Object} Job results
   */
  invoke: async (params, context) => {
    console.log('Starting Active Directory disable user operation');

    const { userDN, dry_run = false } = params;

    if (dry_run) {
      console.log('DRY RUN: No changes will be made to Active Directory');
      return {
        status: 'dry_run_completed',
        userDN,
        disabled: false
      };
    }

    // Get LDAP server URL using shared utility
    const address = getBaseURL(params, context);

    // Get bind credentials from secrets
    const bindDN = context.secrets.LDAP_BIND_DN;
    const bindPassword = context.secrets.LDAP_BIND_PASSWORD;

    if (!bindDN || !bindPassword) {
      throw new Error('Missing LDAP bind credentials. Provide LDAP_BIND_DN and LDAP_BIND_PASSWORD in secrets.');
    }

    // Build TLS options
    const tlsOptions = {};
    if (context.environment?.TLS_SKIP_VERIFY === 'true') {
      tlsOptions.rejectUnauthorized = false;
    }

    const client = new ldapts.Client({
      url: address,
      tlsOptions
    });

    try {
      console.log(`Binding to LDAP server at ${address}`);
      await client.bind(bindDN, bindPassword);

      console.log(`Disabling user ${userDN}`);
      const { disabled, previousUAC, newUAC } = await disableUser(userDN, client);

      if (disabled) {
        console.log(`Successfully disabled user ${userDN} (UAC ${previousUAC} -> ${newUAC})`);
      } else {
        console.log(`User ${userDN} is already disabled (UAC ${previousUAC})`);
      }

      return {
        status: 'success',
        userDN,
        disabled,
        previousUAC,
        newUAC,
        address
      };
    } catch (error) {
      console.error(`Error disabling user: ${error.message}`);
      throw error;
    } finally {
      await client.unbind();
    }
  },

  /**
   * Error recovery handler - framework handles retries by default
   * @param {Object} params - Original params plus error information
   * @param {Object} _context - Execution context
   */
  error: async (params, _context) => {
    const { error, userDN } = params;
    console.error(`Failed to disable AD user ${userDN}: ${error.message}`);

    const errorMessage = error.message.toLowerCase();

    // Authentication errors (fatal - don't retry)
    if (errorMessage.includes('invalid credentials') ||
        errorMessage.includes('authentication') ||
        errorMessage.includes('bind failed')) {
      console.error('Authentication failed - check LDAP_BIND_DN and LDAP_BIND_PASSWORD');
      throw new Error(`LDAP authentication failed: ${error.message}`);
    }

    // Connection errors (retryable)
    if (errorMessage.includes('connection') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('econnrefused')) {
      console.error('Connection error - may be transient, framework will retry');
      throw error;
    }

    // User not found (fatal - don't retry)
    if (errorMessage.includes('not found')) {
      console.error('User not found - check userDN');
      throw new Error(`User not found: ${error.message}`);
    }

    // Insufficient permissions (fatal - don't retry)
    if (errorMessage.includes('insufficient access') ||
        errorMessage.includes('permission denied')) {
      console.error('Insufficient permissions - check service account privileges');
      throw new Error(`Insufficient LDAP permissions: ${error.message}`);
    }

    // Unknown error - re-throw for framework retry
    console.error('Unknown error occurred, allowing framework to retry');
    throw error;
  },

  /**
   * Graceful shutdown handler - performs cleanup
   * @param {Object} params - Original params plus halt reason
   * @param {Object} _context - Execution context
   * @returns {Object} Cleanup results
   */
  halt: async (params, _context) => {
    const { reason, userDN } = params;
    console.log(`Active Directory disable user operation halted: ${reason}`);

    return {
      status: 'halted',
      userDN: userDN || 'unknown',
      reason,
      halted_at: new Date().toISOString()
    };
  }
};

module.exports = script;
