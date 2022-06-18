using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Options;

namespace JWT.Extensions.AspNetCore.Factories
{
    public sealed class DefaultIdentityFactory : IIdentityFactory
    {
        private readonly IOptionsMonitor<JwtAuthenticationOptions> _options;

        public DefaultIdentityFactory(IOptionsMonitor<JwtAuthenticationOptions> options) =>
            _options = options ?? throw new ArgumentNullException(nameof(options));

        IIdentity IIdentityFactory.CreateIdentity(Type type, object payload)
        {
            if (type is null)
                throw new ArgumentNullException(nameof(type));
            if (payload is null)
                throw new ArgumentException(nameof(payload));

            Type targetType = typeof(IDictionary<string, object>);
            if (!targetType.IsAssignableFrom(type))
                throw new ArgumentOutOfRangeException(nameof(type), $"Type {type} is not assignable to {targetType}");

            return CreateIdentity((IDictionary<string, object>)payload);
        }

        /// <summary>
        /// Creates user's identity from user's claims
        /// </summary>
        /// <param name="payload"><see cref="IDictionary{String,String}" /> of user's claims</param>
        /// <returns><see cref="ClaimsIdentity" /></returns>
        public IIdentity CreateIdentity(IDictionary<string, object> payload)
        {
            var claims = payload.Select(p => new Claim(p.Key, p.Value.ToString()));
            return _options.CurrentValue.IncludeAuthenticationScheme ?
                new ClaimsIdentity(claims, JwtAuthenticationDefaults.AuthenticationScheme) :
                new ClaimsIdentity(claims);
        }
    }
}