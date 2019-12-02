using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace JWT
{
    public sealed class JwtAuthenticationHandler : AuthenticationHandler<JwtAuthenticationOptions>
    {
        private readonly IJwtDecoder _jwtDecoder;

        public JwtAuthenticationHandler(
            IJwtDecoder jwtDecoder,
            IOptionsMonitor<JwtAuthenticationOptions> optionsMonitor,
            ILoggerFactory loggerFactory,
            UrlEncoder urlEncoder,
            ISystemClock clock)
            : base(optionsMonitor, loggerFactory, urlEncoder, clock) =>
            _jwtDecoder = jwtDecoder;

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string header = this.Context.Request.Headers[HeaderNames.Authorization];
            var result = GetAuthenticationResult(header);
            return Task.FromResult(result);
        }

        private AuthenticateResult GetAuthenticationResult(string header)
        {
            if (String.IsNullOrEmpty(header))
            {
                this.Logger.LogInformation($"Header {nameof(HeaderNames.Authorization)} is empty, returning no result");
                return AuthenticateResult.NoResult();
            }

            if (!header.StartsWith(this.Scheme.Name, StringComparison.OrdinalIgnoreCase))
            {
                this.Logger.LogInformation($"Header {nameof(HeaderNames.Authorization)} scheme is not {this.Scheme.Name}, returning no result");
                return AuthenticateResult.NoResult();
            }

            var token = header.Substring(this.Scheme.Name.Length).Trim();
            if (String.IsNullOrEmpty(token))
            {
                this.Logger.LogInformation($"Token in header {nameof(HeaderNames.Authorization)} is empty, returning no result");
                return AuthenticateResult.NoResult();
            }

            try
            {
                var dic = _jwtDecoder.DecodeToObject<Dictionary<string, string>>(token, this.Options.Keys, this.Options.VerifySignature);
                var claims = dic.Select(p => new Claim(p.Key, p.Value));
                var identity = new ClaimsIdentity(claims);

                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(identity),
                    new AuthenticationProperties(),
                    this.Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex);
            }
        }
    }
}