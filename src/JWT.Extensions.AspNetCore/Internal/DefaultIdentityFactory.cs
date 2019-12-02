using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace JWT.Internal
{
    internal static class DefaultIdentityFactory
    {
        /// <summary>
        /// Creates user's identity from user's claims
        /// </summary>
        /// <param name="dic"><see cref="IDictionary{String,String}" /> of user's claims</param>
        /// <returns><see cref="ClaimsIdentity" /></returns>
        public static IIdentity CreateIdentity(IDictionary<string, string> dic)
        {
            var claims = dic.Select(p => new Claim(p.Key, p.Value));
            return new ClaimsIdentity(claims);
        }
    }
}