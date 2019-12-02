using System.Net;
using System.Net.Http;
using System.Net.Mime;
using System.Threading.Tasks;
using FluentAssertions;
using JWT.Tests.Common.Models;
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
        private TestServer _server;
        private HttpClient _client;

        [TestInitialize]
        public void TestInitialize()
        {
            var options = new JwtAuthenticationOptions
            {
                Keys = new[] { TestData.Key },
                VerifySignature = true
            };
            _server = CreateServer(options);
            _client = _server.CreateClient();
        }

        [TestCleanup]
        public void TestCleanup()
        {
            _client.Dispose();
            _server.Dispose();
        }

        [TestMethod]
        public async Task Request_Should_Return_Ok_When_Token_Is_Valid()
        {
            var response = await _client.GetAsync("https://example.com/");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        private static TestServer CreateServer(JwtAuthenticationOptions configureOptions)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                    {
                        app.UseAuthentication();

                        app.Use(async (context, next) =>
                        {
                            var request = context.Request;
                            var response = context.Response;

                            var authenticationResult = await context.AuthenticateAsync();
                            if (authenticationResult.Succeeded)
                            {
                                response.StatusCode = (int)HttpStatusCode.OK;
                                response.ContentType = new ContentType("text/json").MediaType;

                                await response.WriteAsync("HELO");
                            }
                            else
                            {
                                await context.ChallengeAsync();
                            }
                        });
                    })
                .ConfigureServices(services =>
                    {
                        services.AddAuthentication(JwtAuthenticationDefaults.AuthenticationScheme)
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