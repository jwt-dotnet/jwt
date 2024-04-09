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
    public class JwtAuthenticationEventsTests
    {
        private static bool _backwardsCompat;


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
            using var response = await client.GetAsync("https://example.com/");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            MyEventsDependency.HandledSuccessfulTicket.Should().BeTrue();
        }

        [TestMethod]
        public async Task Backwards_Compat_Request_Should_Fire_Events()
        {
            using var server = CreateServer(options =>
            {
                options.Keys = TestData.Secrets;
                options.VerifySignature = true;
                options.OnSuccessfulTicket = (logger, ticket) =>
                {
                    _backwardsCompat = true;
                    return AuthenticateResult.Success(ticket);
                };
            });
            using var client = server.CreateClient();

            // Arrange
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                JwtAuthenticationDefaults.AuthenticationScheme,
                TestData.TokenByAsymmetricAlgorithm);

            // Act
            using var response = await client.GetAsync("https://example.com/");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            _backwardsCompat.Should().BeTrue();
        }

        private static TestServer CreateServer(Action<JwtAuthenticationOptions> configureOptions)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseAuthentication();

                    app.Use(async (HttpContext context, Func<Task> next) =>
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
                        .AddJwt(options =>
                        {
                            configureOptions(options);
                        });
                    services.AddTransient<MyEventsDependency>();
                    services.AddTransient<MyEvents>();
                    services.AddSingleton<IAlgorithmFactory>(new DelegateAlgorithmFactory(TestData.RS256Algorithm));
                });

            return new TestServer(builder);
        }

        public class MyEventsDependency
        {
            public static bool HandledSuccessfulTicket = false;

            public void Mark()
            {
                HandledSuccessfulTicket = true;
            }
        }

        public class MyEvents : JwtAuthenticationEvents
        {
            private readonly MyEventsDependency _dependency;

            public MyEvents(MyEventsDependency dependency)
            {
                _dependency = dependency;
            }

            public override AuthenticateResult SuccessfulTicket(SuccessfulTicketContext context)
            {
                _dependency.Mark();
                return base.SuccessfulTicket(context);
            }
        }
    }
}
