using System;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;
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
    public class JwtAuthenticationEventsIntegrationTests
    {
        private static CancellationToken _cancellationToken;

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            _cancellationToken = context.CancellationTokenSource.Token;
        }

        [TestMethod]
        public async Task Request_Should_Fire_Events()
        {
            using var server = CreateServer(options =>
            {
                options.Keys = TestData.Secrets;
                options.VerifySignature = true;
                options.EventsType = typeof(MyEvents);
            });

            using var client = server.CreateClient();

            // Arrange
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                JwtAuthenticationDefaults.AuthenticationScheme,
                TestData.TokenByAsymmetricAlgorithm);

            // Act
            using var response = await client.GetAsync("https://example.com/", _cancellationToken);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);

            server.Services.GetRequiredService<MyEventsDependency>().HandledSuccessfulTicket.Should().BeTrue();
        }

        [TestMethod]
        public async Task Backwards_Compat_Request_Should_Fire_Events()
        {
            bool backwardsCompat = false;

            using var server = CreateServer(options =>
            {
                options.Keys = TestData.Secrets;
                options.VerifySignature = true;
                options.OnSuccessfulTicket = (_, ticket) =>
                {
                    backwardsCompat = true;
                    return AuthenticateResult.Success(ticket);
                };
            });
            using var client = server.CreateClient();

            // Arrange
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                JwtAuthenticationDefaults.AuthenticationScheme,
                TestData.TokenByAsymmetricAlgorithm);

            // Act
            using var response = await client.GetAsync("https://example.com/", _cancellationToken);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            backwardsCompat.Should().BeTrue();
        }

        private static TestServer CreateServer(Action<JwtAuthenticationOptions> configureOptions)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseAuthentication();

                    app.Use(async (HttpContext context, Func<Task> _) =>
                    {
                        var authenticationResult = await context.AuthenticateAsync();
                        if (authenticationResult.Succeeded)
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
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
                    services.AddAuthentication(options =>
                        {
                            // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found.
                            options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;

                            // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultChallengeScheme found.
                            options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
                        })
                        .AddJwt(options => configureOptions(options));

                    services.AddTransient<MyEventsDependency>()
                            .AddTransient<MyEvents>()
                            .AddSingleton<IAlgorithmFactory>(new DelegateAlgorithmFactory(TestData.RS256Algorithm));
                });
            return new TestServer(builder);
        }

        private sealed class MyEventsDependency
        {
            public bool HandledSuccessfulTicket { get; private set; }

            public void Set() =>
                this.HandledSuccessfulTicket = true;
        }

        private sealed class MyEvents : JwtAuthenticationEvents
        {
            private readonly MyEventsDependency _dependency;

            public MyEvents(MyEventsDependency dependency) =>
                _dependency = dependency;

            public override AuthenticateResult SuccessfulTicket(SuccessfulTicketContext context)
            {
                _dependency.Set();
                return base.SuccessfulTicket(context);
            }
        }
    }
}