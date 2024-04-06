namespace JWT.Extensions.AspNetCore
{
    using System;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.Logging;
    using Microsoft.Net.Http.Headers;

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

        public Func<ILogger, AuthenticateResult> OnMissingHeader { get; set; } =
            logger =>
            {
                _logMissingHeader(logger, null);
                return AuthenticateResult.NoResult();
            };

        public Func<ILogger, string, string, AuthenticateResult> OnIncorrectScheme { get; set; } =
            (logger, actualScheme, expectedScheme) =>
            {
                _logIncorrectScheme(logger, actualScheme, expectedScheme, null);
                return AuthenticateResult.NoResult();
            };

        public Func<ILogger, string, AuthenticateResult> OnEmptyHeader { get; set; } = (logger, header) =>
        {
            _logEmptyHeader(logger, null);
            return AuthenticateResult.NoResult();
        };

        public Func<ILogger, AuthenticationTicket, AuthenticateResult> OnSuccessfulTicket { get; set; } =
            (logger, ticket) =>
            {
                _logSuccessfulTicket(logger, null);
                return AuthenticateResult.Success(ticket);
            };

        public Func<ILogger, Exception, AuthenticateResult> OnFailedTicket { get; set; } = (logger, ex) =>
        {
            _logFailedTicket(logger, ex.Message, ex);
            return AuthenticateResult.Fail(ex);
        };

        public virtual AuthenticateResult SuccessfulTicket(ILogger logger, AuthenticationTicket ticket)
        {
            return OnSuccessfulTicket(logger, ticket);
        }

        public virtual AuthenticateResult FailedTicket(ILogger logger, Exception exception)
        {
            return OnFailedTicket(logger, exception);
        }

        public virtual AuthenticateResult EmptyHeader(ILogger logger, string header)
        {
            return OnEmptyHeader(logger, header);

        }

        public virtual AuthenticateResult IncorrectScheme(ILogger logger, string actualScheme, string expectedScheme)
        {
            return OnIncorrectScheme(logger, actualScheme, expectedScheme);
        }

        public virtual AuthenticateResult MissingHeader(ILogger logger)
        {
            return OnMissingHeader(logger);
        }
    }
}
