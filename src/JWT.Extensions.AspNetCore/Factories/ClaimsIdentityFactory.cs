using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Options;

namespace JWT.Extensions.AspNetCore.Factories
{
    public class ClaimsIdentityFactory : IIdentityFactory
    {
        private readonly IOptionsMonitor<JwtAuthenticationOptions> _options;

        public ClaimsIdentityFactory(IOptionsMonitor<JwtAuthenticationOptions> options) =>
            _options = options ?? throw new ArgumentNullException(nameof(options));

        public IIdentity CreateIdentity(Type type, object payload)
        {
            if (type is null)
                throw new ArgumentNullException(nameof(type));
            if (payload is null)
                throw new ArgumentException(nameof(payload));

            var claims = ReadClaims(type, payload);
            return CreateIdentity(claims);
        }

        protected virtual IEnumerable<Claim> ReadClaims(Type type, object payload)
        {
            Type targetType = typeof(IDictionary<string, object>);
            if (!targetType.IsAssignableFrom(type))
                throw new ArgumentOutOfRangeException(nameof(type), $"Type {type} is not assignable to {targetType}");
 
            var dic = (IDictionary<string, object>)payload;
            return dic.Select(p => new Claim(p.Key, p.Value.ToString()));
        }

        private IIdentity CreateIdentity(IEnumerable<Claim> claims) =>
            _options.CurrentValue.IncludeAuthenticationScheme ?
                new ClaimsIdentity(claims, JwtAuthenticationDefaults.AuthenticationScheme) :
                new ClaimsIdentity(claims);
    }
}
