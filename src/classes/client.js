const { default: UserManager } = require('@misakey/core/auth/classes/UserManager');

const httpApi = require('../httpApi');
const { default: validateProperties } = require('@misakey/core/helpers/validateProperties');

class MisakeyClient {
  constructor({ organizationId, redirectUri }) {
    const err = validateProperties({ organizationId, redirectUri });
    if (err) { throw err; }

    this.userManager = new UserManager({
      authority: `${httpApi.AUTH_URL_PREFIX}/_`,
      clientId: organizationId,
      redirectUri,
    });
  }

  async userConsent(dataSubject, scopes = [], authProps) {
    if (!scopes.includes('openid')) { scopes.push('openid'); }
    if (!scopes.includes('tos')) { scopes.push('tos'); }
    if (!scopes.includes('privacy_policy')) { scopes.push('privacy_policy'); }
    
    return this.userManager.signinRedirect({
      ...authProps,
      scope: scopes.join(' '),
      loginHint: dataSubject,
    });
  }

  async validateUserConsent(args) {
    return this.userManager.signinCallback(args);
  }
}

module.exports = MisakeyClient;
