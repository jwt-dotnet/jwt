using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtBuilderEncodeTests
    {
        private readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Build_Token()
        {
            var algorithm = new HMACSHA256Algorithm();
            var builder = new JwtBuilder();
            var secret = _fixture.Create<string>();

            var tokenBuilt = builder
                .WithAlgorithm(algorithm)
                .WithSecret(secret)
                .Build();

            tokenBuilt.Should()
                      .NotBeEmpty("because the token should contains some data");

            tokenBuilt.Split('.').Should()
                      .HaveCount(3, "because the built token should have the three standard parts");
        }

        [TestMethod]
        public void Build_WithPayload()
        {
            var algorithm = new HMACSHA256Algorithm();
            var builder = new JwtBuilder();
            const ClaimName claimKey = ClaimName.ExpirationTime;
            var claimValue = DateTime.UtcNow
                                     .AddHours(1)
                                     .ToString(CultureInfo.InvariantCulture);
            var secret = _fixture.Create<string>();

            var tokenBuilt = builder
                .WithAlgorithm(algorithm)
                .WithSecret(secret)
                .AddClaim(claimValue, claimKey)
                .Build();

            tokenBuilt.Should()
                      .NotBeEmpty("because the token should contains some data");

            tokenBuilt.Split('.')
                      .Should()
                      .HaveCount(3, "because the built token should have the three standard parts");
        }

        [TestMethod]
        public void Build_WithPayloadWithClaims()
        {
            var algorithm = new HMACSHA256Algorithm();
            var claims = new Dictionary<string, object>();
            var builder = new JwtBuilder();
            var secret = _fixture.Create<string>();

            var nbClaims = _fixture.Create<int>();
            var claimKeys = new string[nbClaims];
            var claimValues = new string[nbClaims];

            for (var i = 0; i < nbClaims; ++i)
            {
                claimKeys[i] = _fixture.Create<string>();
                claimValues[i] = _fixture.Create<string>();

                claims.Add(claimKeys[i], claimValues[i]);
            }

            var tokenBuilt = builder
                .WithAlgorithm(algorithm)
                .WithSecret(secret)
                .AddClaims(claims)
                .Build();

            var decodedToken = Encoding.UTF8.GetString(
                new JwtBase64UrlEncoder()
                    .Decode(tokenBuilt.Split('.')[1]));

            tokenBuilt.Should()
                      .NotBeEmpty("because the token should contains some data");

            tokenBuilt.Split('.')
                      .Should()
                      .HaveCount(3, "because the built token should have the three standard parts");

            decodedToken.Should()
                        .ContainAll(claimKeys, "because all used keys should be retrieved in the token");

            decodedToken.Should()
                        .ContainAll(claimValues, "because all values associated with the claims should be retrieved in the token");
        }

        [TestMethod]
        public void Build_WithoutDependencies_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action buildWithoutDependencies =
                () => builder.Build();

            buildWithoutDependencies.Should()
                                    .Throw<InvalidOperationException>("because a JWT can't be built without dependencies");
        }

        [TestMethod]
        public void Build_WithSymmetricAlgorithm_WithoutSecret_Should_Throw_Exception()
        {
            var algorithm = new HMACSHA256Algorithm();
            var builder = new JwtBuilder();

            Action buildWithoutSecret =
                () => builder.WithAlgorithm(algorithm).Build();

            buildWithoutSecret.Should()
                              .Throw<InvalidOperationException>("because a JWT can't be built with a symmetric algorithm and without a secret");
        }

        [TestMethod]
        public void Build_WithoutAlgorithm_WithSecret_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            var secret = _fixture.Create<string>();

            Action buildJwtWithoutAlgorithm =
                () => builder.WithSecret(secret).Build();

            buildJwtWithoutAlgorithm.Should()
                                    .Throw<InvalidOperationException>("because a JWT should not be created if no algorithm is provided");
        }

        [TestMethod]
        public void Build_WithMultipleSecrets_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            var secrets = _fixture.Create<string[]>();

            Action buildJwtWithoutAlgorithm =
                () => builder.WithSecret(secrets).Build();

            buildJwtWithoutAlgorithm.Should()
                                    .Throw<InvalidOperationException>("because a JWT should not be created if no algorithm is provided");
        }
    }
}
