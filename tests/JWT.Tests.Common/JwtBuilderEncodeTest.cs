using System;
using System.Globalization;
using System.Text;
using JWT.Algorithms;
using JWT.Builder;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtBuilderEncodeTest
    {
        [Fact]
        public void Build_Token()
        {
            var token = new JwtBuilder()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
                .Build();
            Assert.True(token.Length > 0 && token.Split('.').Length == 3);
        }

        [Fact]
        public void Build_WithPayload()
        {
            var testtime = DateTime.UtcNow.AddHours(5).ToString(CultureInfo.InvariantCulture);
            var token = new JwtBuilder()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
                .AddClaim(ClaimName.ExpirationTime, testtime)
                .Build();
            Assert.True(token.Length > 0 && token.Split('.').Length == 3);

            var decodedToken = Encoding.UTF8.GetString(new JwtBase64UrlEncoder().Decode(token.Split('.')[1]));
            Assert.True(decodedToken.Contains("exp") && decodedToken.Contains(testtime));
        }

        [Fact]
        public void Build_WithoutDependencies_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                         .Build());
        }

        [Fact]
        public void Build_WithSymmetricAlgorithm_WithoutSecret_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                         .WithAlgorithm(new HMACSHA256Algorithm())
                                         .Build());
        }

        [Fact]
        public void Build_WithAsymmetricAlgorithm_WithoutSecret_Should_Throw_Exception()
        {
            // TODO: add a test with an asymmetric algorithm
        }

        [Fact]
        public void Build_WithoutAlgorithm_WithSecret_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                         .WithSecret("fjhsdghflghlk")
                                         .Build());
        }

        [Fact]
        public void Build_WithMultipleSecrets_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                .WithSecret(new []{ "fjhsdghflghlk", "wrouhsfjkghure"})
                .Build());
        }
    }
}