using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AutoFixture;
using FluentAssertions;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Extensions.AspNetCore.Tests
{
    [TestClass]
    public class JwtAuthenticationHandlerTests
    {
        private readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public async Task HandleAuthenticateAsync_Should_Return_AuthenticateResult_Success()
        {
            // Arrange
            var serializer = new JsonNetSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var urlEncoder = new JwtBase64UrlEncoder();
            var jwtValidator = new JwtValidator(serializer, dateTimeProvider);
            var decoder = new JwtDecoder(serializer, jwtValidator, urlEncoder);

            var serviceCollection = new ServiceCollection();
            serviceCollection.AddOptions<JwtAuthenticationOptions>()
                             .Configure(options =>
                                  {
                                      options.Keys = new[] { _fixture.Create<string>() };
                                      options.VerifySignature = true;
                                  });
            var optionsMonitor = serviceCollection.BuildServiceProvider()
                                                  .GetService<IOptionsMonitor<JwtAuthenticationOptions>>();

            var loggerFactory = new NullLoggerFactory();
            var encoder = UrlEncoder.Default;
            var clock = new SystemClock();

            var handler = new JwtAuthenticationHandler(decoder, optionsMonitor, loggerFactory, encoder, clock);

            var scheme = new AuthenticationScheme(JwtAuthenticationDefaults.AuthenticationScheme, JwtAuthenticationDefaults.AuthenticationScheme, typeof(JwtAuthenticationHandler));
            var context = new DefaultHttpContext
            {
                Request =
                {
                    Headers =
                    {
                        { HeaderNames.Authorization, $"{JwtAuthenticationDefaults.AuthenticationScheme} {TestData.Token}" }
                    }
                }
            };

            await handler.InitializeAsync(scheme, context);

            // Act
            var result = await handler.AuthenticateAsync();

            // Assert
            result.Succeeded.Should().BeTrue();
        }
    }
}