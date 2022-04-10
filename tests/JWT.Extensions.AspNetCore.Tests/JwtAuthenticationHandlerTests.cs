using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AutoFixture;
using FluentAssertions;
using JWT.Extensions.AspNetCore.Factories;
using JWT.Tests.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

using static JWT.Serializers.JsonSerializerFactory;

namespace JWT.Extensions.AspNetCore.Tests
{
    [TestClass]
    public class JwtAuthenticationHandlerTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public async Task HandleAuthenticateAsync_Should_Return_Success_When_Token_Is_Valid()
        {
            // Arrange
            const string header = $"{JwtAuthenticationDefaults.AuthenticationScheme} {TestData.TokenByAsymmetricAlgorithm}";
            var handler = await CreateHandler(header);

            // Act
            var result = await handler.AuthenticateAsync();

            // Assert
            result.Succeeded.Should().BeTrue();
            result.Ticket.Should().NotBeNull();
            result.Failure.Should().BeNull();

            result.Principal.Should().NotBeNull().And.BeOfType<ClaimsPrincipal>();
            result.Principal.Identity.Should().NotBeNull().And.BeOfType<ClaimsIdentity>();
        }

        [TestMethod]
        public async Task HandleAuthenticateAsync_Should_Return_None_When_Token_Is_Empty()
        {
            // Arrange
            const string header = $"{JwtAuthenticationDefaults.AuthenticationScheme} ";
            var handler = await CreateHandler(header);

            // Act
            var result = await handler.AuthenticateAsync();

            // Assert
            result.None.Should().BeTrue();
            result.Succeeded.Should().BeFalse();
            result.Failure.Should().BeNull();

            result.Ticket.Should().BeNull();
            result.Principal.Should().BeNull();
        }

        [TestMethod]
        public async Task HandleAuthenticateAsync_Should_Return_Fail_When_Token_Is_Invalid()
        {
            // Arrange
            const string header = $"{JwtAuthenticationDefaults.AuthenticationScheme} {TestData.TokenWithIncorrectSignature}";
            var handler = await CreateHandler(header);

            // Act
            var result = await handler.AuthenticateAsync();

            // Assert
            result.None.Should().BeFalse();
            result.Succeeded.Should().BeFalse();
            result.Failure.Should().NotBeNull();

            result.Ticket.Should().BeNull();
            result.Principal.Should().BeNull();
        }

        [TestMethod]
        public async Task HandleAuthenticateAsync_Should_Return_None_When_AuthenticationScheme_Is_Invalid()
        {
            // Arrange
            var header = $"{_fixture.Create<string>()} {_fixture.Create<string>()}";
            var handler = await CreateHandler(header);

            // Act
            var result = await handler.AuthenticateAsync();

            // Assert
            result.None.Should().BeTrue();
            result.Succeeded.Should().BeFalse();
            result.Failure.Should().BeNull();

            result.Ticket.Should().BeNull();
            result.Principal.Should().BeNull();
        }

        private static async Task<JwtAuthenticationHandler> CreateHandler(string header)
        {
            var serializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var urlEncoder = new JwtBase64UrlEncoder();
            var jwtValidator = new JwtValidator(serializer, dateTimeProvider);
            var decoder = new JwtDecoder(serializer, jwtValidator, urlEncoder, TestData.RS256Algorithm);

            var options = new JwtAuthenticationOptions
            {
                Keys = null,
                VerifySignature = true
            };
            var optionsMonitor = new Mock<IOptionsMonitor<JwtAuthenticationOptions>>(MockBehavior.Strict);
            optionsMonitor.Setup(m => m.Get(It.IsAny<string>())).Returns(options);
            optionsMonitor.Setup(m => m.CurrentValue).Returns(options);

            var loggerFactory = NullLoggerFactory.Instance;
            var encoder = UrlEncoder.Default;
            var clock = new SystemClock();

            var handler = new JwtAuthenticationHandler(
                decoder,
                new DefaultIdentityFactory(optionsMonitor.Object),
                new DefaultTicketFactory(),
                optionsMonitor.Object,
                loggerFactory,
                encoder,
                clock);

            var scheme = new AuthenticationScheme(JwtAuthenticationDefaults.AuthenticationScheme, JwtAuthenticationDefaults.AuthenticationScheme, typeof(JwtAuthenticationHandler));
            var context = new DefaultHttpContext
            {
                Request =
                {
                    Headers =
                    {
                        { HeaderNames.Authorization, header }
                    }
                }
            };

            await handler.InitializeAsync(scheme, context);
            return handler;
        }
    }
}