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
        private static readonly Action<ILogger, Exception> _logMissingHeader;
        private static readonly Action<ILogger, string, string, Exception> _logIncorrectScheme;
        private static readonly Action<ILogger, Exception> _logEmptyHeader;
        private static readonly Action<ILogger, Exception> _logSuccessfulTicket;
        private static readonly Action<ILogger, string, Exception> _logFailedTicket;

        private readonly IJwtDecoder _jwtDecoder;
        private readonly IIdentityFactory _identityFactory;
        private readonly ITicketFactory _ticketFactory;

        static JwtAuthenticationHandler()
        {
            _logMissingHeader = LoggerMessage.Define(
                LogLevel.Information,
                10,
                $"Header {nameof(HeaderNames.Authorization)} is empty, returning none");

            _logIncorrectScheme = LoggerMessage.Define<string, string>(
                LogLevel.Information,
                11,
                $"Header {nameof(HeaderNames.Authorization)} scheme is {{0}}, expected {{1}}, returning none");

            _logEmptyHeader = LoggerMessage.Define(
                LogLevel.Information,
                12,
                $"Token in header {nameof(HeaderNames.Authorization)} is empty, returning none");

            _logSuccessfulTicket = LoggerMessage.Define(
                LogLevel.Information,
                1,
                "Successfully decoded JWT, returning success");

            _logFailedTicket = LoggerMessage.Define<string>(
                LogLevel.Information,
                2,
                "Error decoding JWT: {0}, returning failure");
        }

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

        public static AuthenticateResult OnMissingHeader(ILogger logger)
        {
            _logMissingHeader(logger, null);
            return AuthenticateResult.NoResult();
        }

        public static AuthenticateResult OnIncorrectScheme(ILogger logger, string actualScheme, string expectedScheme)
        {
            _logIncorrectScheme(logger, actualScheme, expectedScheme, null);
            return AuthenticateResult.NoResult();
        }

        public static AuthenticateResult OnEmptyHeader(ILogger logger, string header)
        {
            _logEmptyHeader(logger, null);
            return AuthenticateResult.NoResult();
        }

        public static AuthenticateResult OnSuccessfulTicket(ILogger logger, AuthenticationTicket ticket)
        {
            _logSuccessfulTicket(logger, null);
            return AuthenticateResult.Success(ticket);
        }

        public static AuthenticateResult OnFailedTicket(ILogger logger, Exception ex)
        {
            _logFailedTicket(logger, ex.Message, ex);
            return AuthenticateResult.Fail(ex);
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
                return this.Options.OnMissingHeader(this.Logger);

            if (!header.StartsWith(this.Scheme.Name, StringComparison.OrdinalIgnoreCase))
                return this.Options.OnIncorrectScheme(this.Logger, header.Split(' ').FirstOrDefault(), this.Scheme.Name);

            var token = header.Substring(this.Scheme.Name.Length).Trim();
            if (String.IsNullOrEmpty(token))
                return this.Options.OnEmptyHeader(this.Logger, header);

            try
            {
                object payload = _jwtDecoder.DecodeToObject(this.Options.PayloadType, token, this.Options.Keys, this.Options.VerifySignature);
                var identity = _identityFactory.CreateIdentity(this.Options.PayloadType, payload);
                var ticket = _ticketFactory.CreateTicket(identity, this.Scheme);

                return this.Options.OnSuccessfulTicket(this.Logger, ticket);
            }
            catch (Exception ex)
            {
                return this.Options.OnFailedTicket(this.Logger, ex);
            }
        }
    }
}