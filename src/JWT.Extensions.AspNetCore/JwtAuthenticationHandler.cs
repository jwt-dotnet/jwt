using System;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JWT.Extensions.AspNetCore.Factories;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace JWT.Extensions.AspNetCore
{
    public sealed class JwtAuthenticationHandler : AuthenticationHandler<JwtAuthenticationOptions>
    {
        private readonly IJwtDecoder _jwtDecoder;
        private readonly IIdentityFactory _identityFactory;
        private readonly ITicketFactory _ticketFactory;

        public JwtAuthenticationHandler(
            IJwtDecoder jwtDecoder,
            IIdentityFactory identityFactory,
            ITicketFactory ticketFactory,
            IOptionsMonitor<JwtAuthenticationOptions> optionsMonitor,
            ILoggerFactory loggerFactory,
            UrlEncoder urlEncoder,
            ISystemClock clock)
            : base(optionsMonitor, loggerFactory, urlEncoder, clock)
        {
            _jwtDecoder = jwtDecoder;
            _identityFactory = identityFactory;
            _ticketFactory = ticketFactory;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var header = this.Context.Request.Headers[HeaderNames.Authorization];
            var result = GetAuthenticationResult(header);
            return Task.FromResult(result);
        }

        private AuthenticateResult GetAuthenticationResult(string header)
        {
            if (String.IsNullOrEmpty(header))
                return this.Events.MissingHeader(this.Logger);

            if (!header.StartsWith(this.Scheme.Name, StringComparison.OrdinalIgnoreCase))
                return this.Events.IncorrectScheme(this.Logger, header.Split(' ').FirstOrDefault(), this.Scheme.Name);

            var token = header.Substring(this.Scheme.Name.Length).Trim();
            if (String.IsNullOrEmpty(token))
                return this.Events.EmptyHeader(this.Logger, header);

            try
            {
                object payload = _jwtDecoder.DecodeToObject(this.Options.PayloadType, token, this.Options.Keys, this.Options.VerifySignature);
                var identity = _identityFactory.CreateIdentity(this.Options.PayloadType, payload);
                var ticket = _ticketFactory.CreateTicket(identity, this.Scheme);

                var successContext = new SuccessfulTicketContext(this.Logger, ticket, this.Context, this.Options);
                return this.Events.SuccessfulTicket(successContext);
            }
            catch (Exception ex)
            {
                var failedContext = new FailedTicketContext(this.Logger, ex, this.Context, this.Options);
                return this.Events.FailedTicket(failedContext);
            }
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided, a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new JwtAuthenticationEvents Events
        {
            get => (JwtAuthenticationEvents)base.Events!;
            set => base.Events = value;
        }
    }
}
