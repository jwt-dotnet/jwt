using System.Collections.Generic;
using System.Security.Claims;
using FluentAssertions;
using JWT.Extensions.AspNetCore.Factories;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace JWT.Extensions.AspNetCore.Tests
{
    [TestClass]
    public class ClaimsIdentityFactoryTests
    {
        private const string CustomScheme = "Custom";

        [TestMethod]
        public void CreateIdentity_Should_Map_Null_Claim_To_Empty_Json_Null_Claim()
        {
            // Arrange
            var optionsMonitor = new Mock<IOptionsMonitor<JwtAuthenticationOptions>>();
            optionsMonitor.Setup(m => m.CurrentValue).Returns(new JwtAuthenticationOptions());
            var factory = new ClaimsIdentityFactory(optionsMonitor.Object);

            var payload = new Dictionary<string, object>
            {
                ["sub"] = "alice",
                ["middle_name"] = null
            };

            // Act
            var identity = (ClaimsIdentity)factory.CreateIdentity(payload);

            // Assert
            identity.FindFirst("sub").Value.Should().Be("alice");

            var claim = identity.FindFirst("middle_name");
            claim.Should().NotBeNull();
            claim.Value.Should().BeEmpty();
            claim.ValueType.Should().Be("JSON_NULL");
        }

        [TestMethod]
        public void CreateIdentity_Should_Use_Name_Of_Scheme_As_AuthenticationType()
        {
            // Arrange
            var factory = CreateFactory(new JwtAuthenticationOptions());

            // Act
            var identity = factory.CreateIdentity(typeof(Dictionary<string, object>), CreatePayload(), CreateScheme());

            // Assert
            identity.IsAuthenticated.Should().BeTrue();
            identity.AuthenticationType.Should().Be(CustomScheme);
        }

        [TestMethod]
        public void CreateIdentity_Should_Return_Unauthenticated_Identity_When_Scheme_Options_Exclude_AuthenticationScheme()
        {
            // Arrange
            var factory = CreateFactory(new JwtAuthenticationOptions { IncludeAuthenticationScheme = false });

            // Act
            var identity = factory.CreateIdentity(typeof(Dictionary<string, object>), CreatePayload(), CreateScheme());

            // Assert
            identity.IsAuthenticated.Should().BeFalse();
            identity.AuthenticationType.Should().BeNull();
        }

        private static ClaimsIdentityFactory CreateFactory(JwtAuthenticationOptions schemeOptions)
        {
            // Strict, so reading CurrentValue instead of the scheme's named options fails the test
            var optionsMonitor = new Mock<IOptionsMonitor<JwtAuthenticationOptions>>(MockBehavior.Strict);
            optionsMonitor.Setup(m => m.Get(CustomScheme)).Returns(schemeOptions);
            return new ClaimsIdentityFactory(optionsMonitor.Object);
        }

        private static AuthenticationScheme CreateScheme() =>
            new AuthenticationScheme(CustomScheme, CustomScheme, typeof(JwtAuthenticationHandler));

        private static Dictionary<string, object> CreatePayload() =>
            new Dictionary<string, object>
            {
                ["sub"] = "alice"
            };
    }
}