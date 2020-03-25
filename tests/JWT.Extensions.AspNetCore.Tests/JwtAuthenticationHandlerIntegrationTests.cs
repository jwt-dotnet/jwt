using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Threading.Tasks;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Tests.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Extensions.AspNetCore.Tests
{
    [TestClass]
    public class JwtAuthenticationHandlerIntegrationTests
    {
        private static readonly Fixture _fixture = new Fixture();
        private static TestServer _server;

        private HttpClient _client;

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            var options = new JwtAuthenticationOptions
            {
                Keys = TestData.Secrets,
                VerifySignature = true
            };
            _server = CreateServer(options);
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            _server.Dispose();
        }

        [TestInitialize]
        public void TestInitialize()
        {
            _client = _server.CreateClient();
        }

        [TestCleanup]
        public void TestCleanup()
        {
            _client.Dispose();
        }

        [TestMethod]
        public async Task Request_Should_Return_Ok_When_Token_Is_Valid()
        {
            // Arrange
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                JwtAuthenticationDefaults.AuthenticationScheme,
                TestData.Token);

            // Act
            var response = await _client.GetAsync("https://example.com/");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [TestMethod]
        public async Task Request_Should_Return_Unauthorized_When_Token_Is_Empty()
        {
            // Arrange
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                JwtAuthenticationDefaults.AuthenticationScheme,
                String.Empty);

            // Act
            var response = await _client.GetAsync("https://example.com/");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [TestMethod]
        public async Task Request_Should_Return_Unauthorized_When_Token_Is_Invalid()
        {
            // Arrange
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                JwtAuthenticationDefaults.AuthenticationScheme,
                TestData.TokenWithIncorrectSignature);

            // Act
            var response = await _client.GetAsync("https://example.com/");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [TestMethod]
        public async Task Request_Should_Return_Unauthorized_When_AuthenticationScheme_Is_Invalid()
        {
            // Arrange
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                _fixture.Create<string>(),
                _fixture.Create<string>());

            // Act
            var response = await _client.GetAsync("https://example.com/");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        private static TestServer CreateServer(JwtAuthenticationOptions configureOptions)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                    {
                        app.UseAuthentication();

                        app.Use(async (context, next) =>
                        {
                            var authenticationResult = await context.AuthenticateAsync();
                            if (authenticationResult.Succeeded)
                            {
                                context.Response.StatusCode = (int)HttpStatusCode.OK;
                                context.Response.ContentType = new ContentType("text/json").MediaType;

                                await context.Response.WriteAsync("Hello");
                            }
                            else
                            {
                                await context.ChallengeAsync();
                            }
                        });
                    })
                .ConfigureServices(services =>
                          {
                              services.AddSingleton<IAlgorithmFactory, HMACSHAAlgorithmFactory>();

                              services.AddAuthentication(options =>
                                           {
                                         // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found.
                                         options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;

                                         // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultChallengeScheme found.
                                         options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
                                           })
                                      .AddJwt(options =>
                                           {
                                               options.Keys = configureOptions.Keys;
                                               options.VerifySignature = configureOptions.VerifySignature;
                                           });
                          });

            return new TestServer(builder);
        }
    }
}