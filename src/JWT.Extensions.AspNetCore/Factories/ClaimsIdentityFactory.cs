using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace JWT.Extensions.AspNetCore.Factories
{
    public class ClaimsIdentityFactory : IIdentityFactory
    {
        // Matches JsonClaimValueTypes.JsonNull from Microsoft.IdentityModel
        private const string JsonNullClaimValueType = "JSON_NULL";

        private readonly IOptionsMonitor<JwtAuthenticationOptions> _options;

        public ClaimsIdentityFactory(IOptionsMonitor<JwtAuthenticationOptions> options) =>
            _options = options ?? throw new ArgumentNullException(nameof(options));

        public IIdentity CreateIdentity(Type type, object payload) =>
            CreateIdentity(type, payload, JwtAuthenticationDefaults.AuthenticationScheme, _options.CurrentValue);

        /// <summary>
        /// Creates <see cref="IIdentity" /> from the payload of the specified type using the name and the options of the specified scheme.
        /// </summary>
        public IIdentity CreateIdentity(Type type, object payload, AuthenticationScheme scheme)
        {
            if (scheme is null)
                throw new ArgumentNullException(nameof(scheme));

            return CreateIdentity(type, payload, scheme.Name, _options.Get(scheme.Name));
        }

        protected virtual IEnumerable<Claim> ReadClaims(Type type, object payload)
        {
            Type targetType = typeof(IDictionary<string, object>);
            if (!targetType.IsAssignableFrom(type))
                throw new ArgumentOutOfRangeException(nameof(type), $"Type {type} is not assignable to {targetType}");
 
            var dic = (IDictionary<string, object>)payload;
            return dic.Select(p => p.Value is null ?
                new Claim(p.Key, String.Empty, JsonNullClaimValueType) :
                new Claim(p.Key, p.Value.ToString()));
        }

        private IIdentity CreateIdentity(Type type, object payload, string authenticationType, JwtAuthenticationOptions options)
        {
            if (type is null)
                throw new ArgumentNullException(nameof(type));
            if (payload is null)
                throw new ArgumentException(nameof(payload));

            var claims = ReadClaims(type, payload);
            return options.IncludeAuthenticationScheme ?
                new ClaimsIdentity(claims, authenticationType) :
                new ClaimsIdentity(claims);
        }
    }
}
