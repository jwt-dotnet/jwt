using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace JWT.Factory
{
    public sealed class DefaultIdentityFactory : IIdentityFactory
    {
        private readonly JwtAuthenticationOptions _options;

        public DefaultIdentityFactory(JwtAuthenticationOptions options) =>
            _options = options;

        /// <summary>
        /// Creates user's identity from user's claims
        /// </summary>
        /// <param name="payload"><see cref="IDictionary{String,String}" /> of user's claims</param>
        /// <returns><see cref="ClaimsIdentity" /></returns>
        public IIdentity CreateIdentity(IDictionary<string, string> payload)
        {
            var claims = payload.Select(p => new Claim(p.Key, p.Value));
            return _options.IncludeAuthenticationScheme ?
                new ClaimsIdentity(claims, JwtAuthenticationDefaults.AuthenticationScheme) :
                new ClaimsIdentity(claims);
        }
    }
}