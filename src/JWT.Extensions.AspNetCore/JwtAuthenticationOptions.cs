using System;
using System.Collections.Generic;
using System.Security.Principal;
using JWT.Internal;
using Microsoft.AspNetCore.Authentication;

namespace JWT
{
    public class JwtAuthenticationOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// The keys used to sign the JWT.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">Plain-text secret for HMACSHA algorithms.</list>
        /// <list type="bullet">Public Key for RS algorithms.</list>
        /// </remarks>
        public string[] Keys { get; set; }

        /// <summary>
        /// The flag whether to verify the signature or not. The default value is <see langword="true" />.
        /// </summary>
        public bool VerifySignature { get; set; } = true;

        /// <summary>
        /// Creates user's <see cref="IIdentity" /> from <see cref="IDictionary{String,String}" /> of user's claims
        /// </summary>
        /// <remarks>
        /// For the default behavior <see cref="DefaultIdentityFactory.CreateIdentity" />.
        /// </remarks>
        public Func<IDictionary<string, string>, IIdentity> IdentityFactory { get; set; } = DefaultIdentityFactory.CreateIdentity;

        /// <summary>
        /// Creates user's <see cref="AuthenticationTicket" /> from user's <see cref="IIdentity" /> and current <see cref="AuthenticationScheme" />
        /// </summary>
        /// <remarks>
        /// For the default behavior <see cref="DefaultTicketFactory.CreateTicket" />.
        /// </remarks>
        public Func<IIdentity, AuthenticationScheme, AuthenticationTicket> TicketFactory { get; set; } = DefaultTicketFactory.CreateTicket;
    }
}