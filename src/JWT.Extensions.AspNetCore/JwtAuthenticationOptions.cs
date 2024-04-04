using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

namespace JWT.Extensions.AspNetCore
{
    public class JwtAuthenticationOptions : AuthenticationSchemeOptions
    {
        public JwtAuthenticationOptions()
        {
            Events = new JwtAuthenticationEvents();
        }

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
        /// Handles missing authentication header.
        /// </summary>
        /// <remarks>
        /// For the default behavior <see cref="JwtAuthenticationEvents.OnMissingHeader" />.
        /// </remarks>
        [Obsolete("Use Events.OnMissingHeader")]
        public Func<ILogger, AuthenticateResult> OnMissingHeader { get; set; } = JwtAuthenticationEvents.OnMissingHeader;

        /// <summary>
        /// Handles incorrect authentication scheme.
        /// </summary>
        /// <remarks>
        /// For the default behavior <see cref="JwtAuthenticationEvents.OnIncorrectScheme" />.
        /// </remarks>
        [Obsolete("Use Events.OnIncorrectScheme")]
        public Func<ILogger, string, string, AuthenticateResult> OnIncorrectScheme { get; set; } = JwtAuthenticationEvents.OnIncorrectScheme;

        /// <summary>
        /// Handles empty authentication header.
        /// </summary>
        /// <remarks>
        /// For the default behavior <see cref="JwtAuthenticationEvents.OnEmptyHeader" />.
        /// </remarks>
        [Obsolete("Use Events.OnEmptyHeader")]
        public Func<ILogger, string, AuthenticateResult> OnEmptyHeader { get; set; } = JwtAuthenticationEvents.OnEmptyHeader;

        /// <summary>
        /// Handles successful authentication header.
        /// </summary>
        /// <remarks>
        /// For the default behavior <see cref="JwtAuthenticationEvents.OnSuccessfulTicket" />.
        /// </remarks>
        [Obsolete("Use Events.OnSuccessfulTicket")]
        public Func<ILogger, AuthenticationTicket, AuthenticateResult> OnSuccessfulTicket { get; set; } = JwtAuthenticationEvents.OnSuccessfulTicket;

        /// <summary>
        /// Handles failed authentication header.
        /// </summary>
        /// <remarks>
        /// For the default behavior <see cref="JwtAuthenticationEvents.OnFailedTicket" />.
        /// </remarks>
        [Obsolete("Use Events.OnFailedTicket")]
        public Func<ILogger, Exception, AuthenticateResult> OnFailedTicket { get; set; } = JwtAuthenticationEvents.OnFailedTicket;

        /// <summary>
        /// Whether to include by default AuthenticationScheme into the resulting <see cref="ClaimsIdentity" />.
        /// </summary>
        /// <remarks>
        /// The default value is <c>true</c>.
        /// </remarks>
        public bool IncludeAuthenticationScheme { get; set; } = true;

        /// <summary>
        /// Type of the payload to deserialize to.
        /// </summary>
        /// <remarks>
        /// The default value is <see cref="Dictionary{String, String}" />.
        /// </remarks>
        public Type PayloadType { get; set; } = typeof(Dictionary<string, object>);


        /// <summary>
        /// Custom Event Overrides
        /// </summary>
        public new JwtAuthenticationEvents Events
        {
            get => (JwtAuthenticationEvents)base.Events!;
            set => base.Events = value;
        }
    }
}
