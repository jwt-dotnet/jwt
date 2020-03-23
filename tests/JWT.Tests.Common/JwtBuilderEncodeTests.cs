using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtBuilderEncodeTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Encode_With_Secret()
        {
            var algorithm = new HMACSHA256Algorithm();
            var builder = new JwtBuilder();
            var secret = _fixture.Create<string>();

            var token = builder.WithAlgorithm(algorithm)
                               .WithSecret(secret)
                               .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the built token should have the three standard parts");
        }

        [TestMethod]
        public void Encode_With_Certificate()
        {
            var algorithm = TestData.RS256Algorithm;
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(algorithm)
                               .AddClaim("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
                               .AddClaim("name", TestData.Customer.FirstName)
                               .AddClaim("iss", "test")
                               .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the built token should have the three standard parts");
        }

        [TestMethod]
        public void Encode_With_CertificateFactory()
        {
            var algFactory = new DelegateAlgorithmFactory(TestData.RS256Algorithm);
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithmFactory(algFactory)
                               .AddClaim("exp", DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds())
                               .AddClaim("name", TestData.Customer.FirstName)
                               .AddClaim("iss", "test")
                               .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the built token should have the three standard parts");
        }

        [TestMethod]
        public void Encode_With_Secret_And_Payload()
        {
            var algorithm = new HMACSHA256Algorithm();
            var builder = new JwtBuilder();
            const ClaimName claimKey = ClaimName.ExpirationTime;
            var claimValue = DateTime.UtcNow.AddHours(1)
                                     .ToString(CultureInfo.InvariantCulture);
            var secret = _fixture.Create<string>();

            var token = builder.WithAlgorithm(algorithm)
                               .WithSecret(secret)
                               .AddClaim(claimValue, claimKey)
                               .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");

            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the built token should have the three standard parts");
        }

        [TestMethod]
        public void Encode_With_PayloadWithClaims()
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

            var token = builder.WithAlgorithm(algorithm)
                               .WithSecret(secret)
                               .AddClaims(claims)
                               .Encode();

            var decodedToken = Encoding.UTF8.GetString(new JwtBase64UrlEncoder().Decode(token.Split('.')[1]));

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");

            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the built token should have the three standard parts");

            decodedToken.Should()
                        .ContainAll(claimKeys, "because all used keys should be retrieved in the token");

            decodedToken.Should()
                        .ContainAll(claimValues, "because all values associated with the claims should be retrieved in the token");
        }

        [TestMethod]
        public void Encode_Without_Dependencies_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action buildWithoutDependencies = () => builder.Encode();

            buildWithoutDependencies.Should()
                                    .Throw<InvalidOperationException>("because a JWT can't be built without dependencies");
        }

        [TestMethod]
        public void Encode_With_SymmetricAlgorithm_WithoutSecret_Should_Throw_Exception()
        {
            var algorithm = new HMACSHA256Algorithm();
            var builder = new JwtBuilder();

            Action buildWithoutSecret = () => builder.WithAlgorithm(algorithm)
                                                     .Encode();

            buildWithoutSecret.Should()
                              .Throw<InvalidOperationException>("because a JWT can't be built with a symmetric algorithm and without a secret");
        }

        [TestMethod]
        public void Encode_With_outAlgorithm_WithSecret_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            var secret = _fixture.Create<string>();

            Action buildJwtWithoutAlgorithm = () => builder.WithSecret(secret)
                                                           .Encode();

            buildJwtWithoutAlgorithm.Should()
                                    .Throw<InvalidOperationException>("because a JWT should not be created if no algorithm is provided");
        }

        [TestMethod]
        public void Encode_With_MultipleSecrets_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            var secrets = _fixture.Create<string[]>();

            Action buildJwtWithoutAlgorithm = () => builder.WithSecret(secrets)
                                                           .Encode();

            buildJwtWithoutAlgorithm.Should()
                                    .Throw<InvalidOperationException>("because a JWT should not be created if no algorithm is provided");
        }
    }
}