using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Builder
{
    [TestClass]
    public class JwtBuilderEncodeTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Encode_With_Secret_Should_Return_Valid_Token()
        {
            var secret = _fixture.Create<string>();

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(secret)
                                  .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the token should consist of three parts");
        }

        [TestMethod]
        public void Encode_With_Secret_And_Payload_Should_Return_Valid_Token()
        {
            const ClaimName claimKey = ClaimName.ExpirationTime;
            var claimValue = DateTime.UtcNow.AddHours(1).ToString(CultureInfo.InvariantCulture);
            var secret = _fixture.Create<string>();

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(secret)
                                  .AddClaim(claimKey, claimValue)
                                  .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");

            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the token should consist of three parts");
        }

        [TestMethod]
        public void Encode_With_PayloadWithClaims_Should_Return_Token()
        {
            var secret = _fixture.Create<string>();
            var claims = Enumerable.Range(0, 3)
                                   .ToDictionary(_ => _fixture.Create<string>(), _ => (object)_fixture.Create<string>());

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(secret)
                                  .AddClaims(claims)
                                  .Encode();

            var decodedToken = new UTF8Encoding(false)
               .GetString(new JwtBase64UrlEncoder()
                             .Decode(token.Split('.')[1]));

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");

            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the token should consist of three parts");

            decodedToken.Should()
                        .ContainAll(claims.Keys, "because all used keys should be retrieved in the token");

            decodedToken.Should()
                        .ContainAll(claims.Values.Cast<string>(), "because all values associated with the claims should be retrieved in the token");
        }

        [TestMethod]
        public void Encode_Without_Dependencies_Should_Throw_Exception()
        {
            Action action = () =>
                JwtBuilder.Create()
                          .Encode();

            action.Should()
                  .Throw<InvalidOperationException>("because a JWT can't be built without dependencies");
        }

        [TestMethod]
        public void Encode_With_SymmetricAlgorithm_WithoutSecret_Should_Throw_Exception()
        {
            Action action =
                () => JwtBuilder.Create()
                                .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                .Encode();

            action.Should()
                  .Throw<ArgumentNullException>("because a JWT can't be built with a symmetric algorithm and without a secret");
        }

        [TestMethod]
        public void Encode_WithoutAlgorithm_WithSecret_Should_Throw_Exception()
        {
            var secret = _fixture.Create<string>();

            Action action = () =>
                JwtBuilder.Create()
                          .WithSecret(secret)
                          .Encode();

            action.Should()
                  .Throw<InvalidOperationException>("because a JWT should not be created if no algorithm is provided");
        }

        [TestMethod]
        public void Encode_With_MultipleSecrets_Should_Throw_Exception()
        {
            var secrets = _fixture.Create<string[]>();

            Action action = () =>
                JwtBuilder.Create()
                          .WithSecret(secrets)
                          .Encode();

            action.Should()
                  .Throw<InvalidOperationException>("because a JWT should not be created if no algorithm is provided");
        }

        [TestMethod]
        public void Encode_With_NoneAlgorithm_Should_Return_Token()
        {
            var secret = _fixture.Create<string>();

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(new NoneAlgorithm())
                                  .WithSecret(secret)
                                  .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the token should consist of three parts");
            token.Split('.')
                 .Last()
                 .Should()
                 .BeEmpty("Because it should miss signature");
        }
        
        [TestMethod]
        public void Encode_With_NoneAlgorithm_Should_Not_Require_Secret()
        {
            var token = JwtBuilder.Create()
                                  .WithAlgorithm(new NoneAlgorithm())
                                  .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the token should consist of three parts");
            token.Split('.')
                 .Last()
                 .Should()
                 .BeEmpty("Because it should miss signature");
        }

        [TestMethod]
        public void Encode_Should_Return_Token_With_Extra_Headers()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddHeader(HeaderName.KeyId, "42")
                                  .AddClaim(nameof(TestData.Customer.FirstName), TestData.Customer.FirstName)
                                  .AddClaim(nameof(TestData.Customer.Age), TestData.Customer.Age)
                                  .Encode();

            token.Should()
                 .Be(TestData.TokenWithCustomTypeHeader2, "because the same data encoded with the same key must result in the same token");
        }

        [TestMethod]
        public void Encode_Should_Return_Token_With_Custom_Extra_Headers()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddHeader("version", 1)
                                  .AddClaim(nameof(TestData.Customer.FirstName), TestData.Customer.FirstName)
                                  .AddClaim(nameof(TestData.Customer.Age), TestData.Customer.Age)
                                  .Encode();

            token.Should()
                 .Be(TestData.TokenWithCustomTypeHeader3, "because the same data encoded with the same key must result in the same token");
        }
        
        [TestMethod]
        public void Encode_Should_Return_Token_With_Custom_Extra_Headers_Full_Payload()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddHeader("version", 1)
                                  .Encode(TestData.Customer);

            token.Should()
                 .Be(TestData.TokenWithCustomTypeHeader3, "because the same data encoded with the same key must result in the same token");
        }
        
        [TestMethod]
        public void Encode_Should_Return_Token_With_Custom_Extra_Headers_Full_Payload_And_Claims()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddHeader("version", 1)
                                  .AddClaim("ExtraClaim", "ValueClaim")
                                  .Encode(TestData.Customer);

            token.Should()
                 .Be(TestData.TokenWithCustomTypeHeader3AndClaim, "because the same data encoded with the same key must result in the same token");
        }
        
        [TestMethod]
        public void Encode_Should_Return_Token_With_Custom_Extra_Headers_Full_Payload_And_Claims_With_Nested()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddHeader("version", 1)
                                  .AddClaim("ExtraClaim", new { NestedProperty1 = "Foo", NestedProperty2 = 3 })
                                  .Encode(TestData.Customer);

            token.Should()
                 .Be(TestData.TokenWithCustomTypeHeader3AndClaimNested, "because the same data encoded with the same key must result in the same token");
        }
        
        [TestMethod]
        public void Encode_Should_Return_Token_With_Custom_Extra_Headers_Full_Payload_And_Claims_With_Nested_TypesMatch()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddHeader("version", 1)
                                  .AddClaim("ExtraClaim", new { NestedProperty1 = "Foo", NestedProperty2 = 3 })
                                  .Encode(typeof(Customer), TestData.Customer);

            token.Should()
                 .Be(TestData.TokenWithCustomTypeHeader3AndClaimNested, "because the same data encoded with the same key must result in the same token");
        }
        
        [TestMethod]
        public void Encode_Should_Return_ThrowTargetException_Encode_TypesMatch()
        {
            const string key = TestData.Secret;

            Action action = () =>
                JwtBuilder.Create()
                          .WithAlgorithm(TestData.HMACSHA256Algorithm)
                          .WithSecret(key)
                          .AddHeader("version", 1)
                          .AddClaim("ExtraClaim", new { NestedProperty1 = "Foo", NestedProperty2 = 3 })
                          .Encode(typeof(string), TestData.Customer);

            if (IsRunningOnMono())
            {
                action.Should()
                      .Throw<TargetInvocationException>("Exception has been thrown by the target of an invocation.");
            }
            else
            {
                action.Should()
                      .Throw<TargetException>("Object does not match target type.");
            }
        }

        /// <summary>
        /// Copied from: https://stackoverflow.com/a/7077620/2890855
        /// </summary>
        /// <returns></returns>
        private static bool IsRunningOnMono() => 
            Type.GetType("Mono.Runtime") is not null;
        
        [TestMethod]
        public void Encode_Should_Return_Token_With_Custom_Extra_Headers_Full_Payload2()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddHeader("version", 1)
                                  .Encode(
                                      new
                                      {
                                          ExtraClaim = new
                                          {
                                              NestedProperty1 = "Foo",
                                              NestedProperty2 = 3
                                          },
                                          FirstName = "Jesus",
                                          Age = 33
                                      });

            token.Should()
                 .Be(TestData.TokenWithCustomTypeHeader3AndClaimNested, "because the same data encoded with the same key must result in the same token");
        }
        
        [TestMethod]
        public void Encode_Should_Return_Token_Nested_Data()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(key)
                                  .AddClaim<Customer>("Data", TestData.Customer)
                                  .Encode();

            token.Should()
                 .Be(TestData.TokenWithNestedData, "because the same data encoded with the same key must result in the same token");
        }

        [TestMethod]
        public void Encode_With_Custom_Factory_Return_Token()
        {
            const string key = TestData.Secret;

            var token = JwtBuilder.Create()
                                  .WithSecret(key)
                                  .WithAlgorithmFactory(new CustomFactory())
                                  .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
        }

        [TestMethod]
        public void Encode_With_Secret_Should_Return_Valid_Token_Using_Json_Net()
        {
            var secret = _fixture.Create<string>();

            var token = JwtBuilder.Create()
                                  .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                  .WithSecret(secret)
                                  .WithJsonSerializer(new JsonNetSerializer())
                                  .Encode();

            token.Should()
                 .NotBeNullOrEmpty("because the token should contains some data");
            token.Split('.')
                 .Should()
                 .HaveCount(3, "because the token should consist of three parts");
        }
        
#if NETSTANDARD2_0 || NET6_0
        [TestMethod]
        public void Encode_Test_Bug438()
        {
            var privateKey = ECDsa.Create();
            var publicKey = ECDsa.Create();;
            
            var algo = new ES256Algorithm(publicKey, privateKey);

            var factory = new DelegateAlgorithmFactory(() => algo);

            var now = DateTime.UtcNow;
            var sessionId = Guid.NewGuid();

            IEnumerable<string> enumerable = new List<string>
            {
                "string1",
                "string2"
            };

            var array = new string[]
            {
                "one",
                "two"
            };
            
            var builder = JwtBuilder.Create()
                                    .WithAlgorithmFactory(factory)
                                    .AddClaim("session_id", sessionId.ToString())
                                    .AddClaim("enumerable", enumerable)
                                    .AddClaim("array", array)
                                    .Issuer("Security Guy")
                                    .Audience("Strict access perimeter")
                                    .IssuedAt(now)
                                    .ExpirationTime(now.AddMinutes(30));

            var token = builder.Encode();

            token.Should()
                 .NotBeNullOrEmpty();
        }
#endif

        private sealed class CustomFactory : IAlgorithmFactory
        {
            public IJwtAlgorithm Create(JwtDecoderContext context) =>
                TestData.HMACSHA256Algorithm;
        }
    }
}
