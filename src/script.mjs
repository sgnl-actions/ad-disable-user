/**
 * Active Directory Disable User Action
 *
 * Disables a user account in on-premise Active Directory by setting
 * the ACCOUNTDISABLE bit (0x0002) in the userAccountControl attribute.
 * If the user is already disabled, returns success with disabled=false.
 */

import { Client, Change, Attribute } from 'ldapts';
import { getBaseURL } from '@sgnl-actions/utils';

/**
 * Escape special characters in LDAP filter values to prevent injection.
 *
 * @param {string} str - The string to escape
 * @returns {string} The escaped string safe for use in LDAP filters
 */
function escapeLDAPFilter(str) {
  return str.replace(/[\\*()\0]/g, (char) => '\\' + char.charCodeAt(0).toString(16).padStart(2, '0'));
}

/**
 * Find a user's Distinguished Name by searching for their sAMAccountName.
 *
 * @param {Client} client - Bound ldapts Client instance
 * @param {string} baseDN - Base DN to search from
 * @param {string} samAccountName - User's sAMAccountName
 * @returns {Promise<string>} The user's Distinguished Name
 * @throws {Error} If user not found or multiple users found
 */
async function findUserDN(client, baseDN, samAccountName) {
  console.log(`Searching for user with sAMAccountName: ${samAccountName}`);

  const escapedSamAccountName = escapeLDAPFilter(samAccountName);
  const { searchEntries } = await client.search(baseDN, {
    scope: 'sub',
    filter: `(&(objectClass=user)(sAMAccountName=${escapedSamAccountName}))`,
    attributes: ['distinguishedName']
  });

  if (!searchEntries || searchEntries.length === 0) {
    throw new Error(`User not found with sAMAccountName: ${samAccountName}`);
  }

  if (searchEntries.length > 1) {
    throw new Error(`Multiple users found with sAMAccountName: ${samAccountName}. Expected exactly one.`);
  }

  const userDN = searchEntries[0].dn;
  console.log(`Found user DN: ${userDN}`);
  return userDN;
}

/**
 * Safely disconnect from LDAP server.
 * Errors during unbind are logged but not thrown to avoid masking original errors.
 *
 * @param {Client} client - The ldapts client
 */
async function safeUnbind(client) {
  if (!client) {
    return;
  }
  try {
    await client.unbind();
  } catch (unbindError) {
    console.warn(`Warning: Error during LDAP unbind: ${unbindError.message}`);
  }
}

/**
 * Disable a user account in Active Directory by setting the ACCOUNTDISABLE bit.
 *
 * @param {string} userDN - Distinguished Name of the user
 * @param {Client} client - Bound ldapts Client instance
 * @returns {Promise<{disabled: boolean, previousUAC: number, newUAC: number}>}
 */
async function disableUser(userDN, client) {
  // Search for current userAccountControl value
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

  // Set the ACCOUNTDISABLE bit while preserving other flags
  const newUAC = uac | 2;

  await client.modify(userDN, [
    new Change({
      operation: 'replace',
      modification: new Attribute({
        type: 'userAccountControl',
        values: [newUAC.toString()]
      })
    })
  ]);

  return { disabled: true, previousUAC: uac, newUAC };
}

export default {
  /**
   * Main execution handler - disables a user account in Active Directory.
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.baseDN - Base DN to search for the user
   * @param {string} params.samAccountName - User's sAMAccountName to lookup
   * @param {string} [params.address] - Optional LDAP server URL override
   * @param {boolean} [params.dry_run] - If true, validate without making changes
   * @param {Object} context - Execution context with environment and secrets
   * @returns {Object} Job results including status, userDN, disabled flag, and UAC values
   */
  invoke: async (params, context) => {
    console.log('Starting Active Directory disable user operation');

    const { baseDN, samAccountName, dry_run = false } = params;

    // Validate required parameters
    if (!baseDN) {
      throw new Error('baseDN is required');
    }
    if (!samAccountName) {
      throw new Error('samAccountName is required');
    }

    console.log(`Planning to disable user with sAMAccountName: ${samAccountName}`);

    // Handle dry run - validate and return without making changes
    if (dry_run) {
      console.log('DRY RUN: No changes will be made to Active Directory');
      return {
        status: 'dry_run_completed',
        baseDN,
        samAccountName,
        userDN: null,
        disabled: false
      };
    }

    // Get LDAP connection details
    const address = getBaseURL(params, context);
    const bindDN = context.secrets.LDAP_BIND_DN;
    const bindPassword = context.secrets.LDAP_BIND_PASSWORD;

    // Validate required secrets
    if (!bindDN || !bindPassword) {
      throw new Error('Missing LDAP bind credentials. Provide LDAP_BIND_DN and LDAP_BIND_PASSWORD in secrets.');
    }

    // Configure LDAP client with timeouts
    const clientOptions = {
      url: address,
      timeout: 10000,
      connectTimeout: 10000
    };

    // Configure TLS options for secure connections
    if (address.startsWith('ldaps://') || context.environment?.TLS_SKIP_VERIFY === 'true') {
      clientOptions.tlsOptions = {
        rejectUnauthorized: context.environment?.TLS_SKIP_VERIFY !== 'true'
      };
    }

    const client = new Client(clientOptions);

    try {
      console.log(`Connecting to LDAP server at ${address}`);
      await client.bind(bindDN, bindPassword);
      console.log('Successfully authenticated to LDAP server');

      // Lookup user DN by sAMAccountName
      const userDN = await findUserDN(client, baseDN, samAccountName);

      console.log(`Disabling user: ${userDN}`);
      const { disabled, previousUAC, newUAC } = await disableUser(userDN, client);

      if (disabled) {
        console.log(`Successfully disabled user "${userDN}" (UAC: ${previousUAC} -> ${newUAC})`);
      } else {
        console.log(`User "${userDN}" is already disabled (UAC: ${previousUAC})`);
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
      console.error(`Failed to disable user: ${error.message}`);
      throw error;
    } finally {
      await safeUnbind(client);
    }
  },

  /**
   * Error recovery handler - classifies errors and determines retry behavior.
   *
   * @param {Object} params - Original params plus error information
   * @param {Error} params.error - The error that occurred
   * @param {string} params.baseDN - The base DN being searched
   * @param {string} params.samAccountName - The sAMAccountName being looked up
   * @param {Object} _context - Execution context (unused)
   * @throws {Error} Re-throws with appropriate classification
   */
  error: async (params, _context) => {
    const { error, baseDN, samAccountName } = params;
    console.error(`Error handler invoked for user "${samAccountName}" in "${baseDN}": ${error.message}`);

    const errorMessage = error.message.toLowerCase();

    // Authentication errors (fatal - don't retry)
    if (errorMessage.includes('invalid credentials') ||
        errorMessage.includes('authentication') ||
        errorMessage.includes('bind failed')) {
      console.error('Authentication failed - check LDAP_BIND_DN and LDAP_BIND_PASSWORD');
      throw new Error(`LDAP authentication failed: ${error.message}`);
    }

    // Connection errors (retryable - framework will retry)
    if (errorMessage.includes('connection') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('econnrefused')) {
      console.error('Connection error - may be transient, framework will retry');
      throw error;
    }

    // User not found (fatal - don't retry)
    if (errorMessage.includes('not found')) {
      console.error('User not found - check samAccountName');
      throw new Error(`User not found: ${error.message}`);
    }

    // Multiple users found (fatal - don't retry)
    if (errorMessage.includes('multiple users found')) {
      console.error('Multiple users found - sAMAccountName should be unique');
      throw new Error(`Multiple users found: ${error.message}`);
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
   * Graceful shutdown handler - called when the job is halted.
   *
   * @param {Object} params - Original params plus halt reason
   * @param {string} params.reason - The reason for the halt
   * @param {string} [params.baseDN] - The base DN being searched
   * @param {string} [params.samAccountName] - The sAMAccountName being looked up
   * @param {Object} _context - Execution context (unused)
   * @returns {Object} Cleanup results with halted status
   */
  halt: async (params, _context) => {
    const { reason, baseDN, samAccountName } = params;
    console.log(`Active Directory disable user operation halted: ${reason}`);

    return {
      status: 'halted',
      baseDN: baseDN || 'unknown',
      samAccountName: samAccountName || 'unknown',
      reason,
      halted_at: new Date().toISOString()
    };
  }
};
