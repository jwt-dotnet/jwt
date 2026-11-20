using System;
using System.Threading.Tasks;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Tests.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Extensions.AspNetCore.Tests
{
    [TestClass]
    public class ClaimsIdentityFactoryIntegrationTests
    {
        private const string CustomScheme = "Custom";

        [TestMethod]
        public async Task AuthenticateAsync_Should_Succeed_When_Token_Has_Null_Claim()
        {
            // Arrange
            var token = JwtBuilder.Create()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret(TestData.Secret)
                .AddClaim("sub", "alice")
                .AddClaim("middle_name", null)
                .Encode();

            using var host = CreateHost(static builder => builder
                .AddJwt<HMACSHAAlgorithmFactory>(static options => options.Keys = TestData.Secrets));

            // Act
            var result = await AuthenticateAsync(host, JwtAuthenticationDefaults.AuthenticationScheme, token);

            // Assert
            result.Succeeded.Should().BeTrue();
            result.Failure.Should().BeNull();

            var claim = result.Principal.FindFirst("middle_name");
            claim.Should().NotBeNull();
            claim.Value.Should().BeEmpty();
            claim.ValueType.Should().Be("JSON_NULL");
        }

        [TestMethod]
        public async Task AuthenticateAsync_Should_Use_Scheme_Name_As_AuthenticationType()
        {
            // Arrange
            using var host = CreateHost(static builder => builder
                .AddJwt<HMACSHAAlgorithmFactory>(CustomScheme, static options => options.Keys = TestData.Secrets));

            // Act
            var result = await AuthenticateAsync(host, CustomScheme, CreateToken());

            // Assert
            result.Succeeded.Should().BeTrue();
            result.Principal.Identity.IsAuthenticated.Should().BeTrue();
            result.Principal.Identity.AuthenticationType.Should().Be(CustomScheme);
        }

        [TestMethod]
        public async Task AuthenticateAsync_Should_Use_Options_Of_Authenticated_Scheme()
        {
            // Arrange
            using var host = CreateHost(static builder => builder
                .AddJwt<HMACSHAAlgorithmFactory>(static options =>
                {
                    options.Keys = TestData.Secrets;
                    options.IncludeAuthenticationScheme = false;
                })
                .AddJwt<HMACSHAAlgorithmFactory>(CustomScheme, static options => options.Keys = TestData.Secrets));

            var token = CreateToken();

            // Act
            var defaultResult = await AuthenticateAsync(host, JwtAuthenticationDefaults.AuthenticationScheme, token);
            var customResult = await AuthenticateAsync(host, CustomScheme, token);

            // Assert
            defaultResult.Succeeded.Should().BeTrue();
            defaultResult.Principal.Identity.IsAuthenticated.Should().BeFalse();
            defaultResult.Principal.Identity.AuthenticationType.Should().BeNull();

            customResult.Succeeded.Should().BeTrue();
            customResult.Principal.Identity.IsAuthenticated.Should().BeTrue();
            customResult.Principal.Identity.AuthenticationType.Should().Be(CustomScheme);
        }

        private static IHost CreateHost(Action<AuthenticationBuilder> configure) =>
            new HostBuilder()
                .ConfigureServices(services => configure(services.AddAuthentication()))
                .Build();

        private static Task<AuthenticateResult> AuthenticateAsync(IHost host, string scheme, string token)
        {
            var context = new DefaultHttpContext
            {
                RequestServices = host.Services
            };
            context.Request.Headers[HeaderNames.Authorization] = $"{scheme} {token}";

            return context.AuthenticateAsync(scheme);
        }

        private static string CreateToken() =>
            JwtBuilder.Create()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret(TestData.Secret)
                .AddClaim("sub", "alice")
                .Encode();
    }
}