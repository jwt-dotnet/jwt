using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace JWT.Extensions.AspNetCore
{
    public class JwtAuthenticationEvents
    {
        private static readonly Action<ILogger, Exception> _logMissingHeader;
        private static readonly Action<ILogger, string, string, Exception> _logIncorrectScheme;
        private static readonly Action<ILogger, Exception> _logEmptyHeader;
        private static readonly Action<ILogger, Exception> _logSuccessfulTicket;
        private static readonly Action<ILogger, string, Exception> _logFailedTicket;

        static JwtAuthenticationEvents()
        {
            _logMissingHeader = LoggerMessage.Define(
                LogLevel.Information,
                10,
                $"Header {nameof(HeaderNames.Authorization)} is empty, returning none");

            _logIncorrectScheme = LoggerMessage.Define<string, string>(
                LogLevel.Information,
                11,
                $"Header {nameof(HeaderNames.Authorization)} scheme is {{ActualScheme}}, expected {{ExpectedScheme}}, returning none");

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

        public Func<ILogger, Task<AuthenticateResult>> OnMissingHeader { get; set; } =
            logger =>
            {
                _logMissingHeader(logger, null);
                return Task.FromResult(AuthenticateResult.NoResult());
            };

        public Func<ILogger, string, string, Task<AuthenticateResult>> OnIncorrectScheme { get; set; } =
            (logger, actualScheme, expectedScheme) =>
            {
                _logIncorrectScheme(logger, actualScheme, expectedScheme, null);
                return Task.FromResult(AuthenticateResult.NoResult());
            };

        public Func<ILogger, string, Task<AuthenticateResult>> OnEmptyHeader { get; set; } = (logger, header) =>
        {
            _logEmptyHeader(logger, null);
            return Task.FromResult(AuthenticateResult.NoResult());
        };

        public Func<SuccessfulTicketContext, Task<AuthenticateResult>> OnSuccessfulTicket { get; set; } = context =>
        {
            _logSuccessfulTicket(context.Logger, null);
            return Task.FromResult(AuthenticateResult.Success(context.Ticket));
        };

        public Func<FailedTicketContext, Task<AuthenticateResult>> OnFailedTicket { get; set; } = context =>
        {
            _logFailedTicket(context.Logger, context.Exception.Message, context.Exception);
            return Task.FromResult(AuthenticateResult.Fail(context.Exception));
        };

        public virtual Task<AuthenticateResult> SuccessfulTicket(SuccessfulTicketContext context) => OnSuccessfulTicket(context);

        public virtual Task<AuthenticateResult> FailedTicket(FailedTicketContext context) => OnFailedTicket(context);

        public virtual Task<AuthenticateResult> EmptyHeader(ILogger logger, string header) => OnEmptyHeader(logger, header);

        public virtual Task<AuthenticateResult> IncorrectScheme(ILogger logger, string actualScheme, string expectedScheme) => OnIncorrectScheme(logger, actualScheme, expectedScheme);

        public virtual Task<AuthenticateResult> MissingHeader(ILogger logger) => OnMissingHeader(logger);

    }
}
