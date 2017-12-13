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
                .SetAlgorithm(new HMACSHA256Algorithm())
                .SetSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
                .Build();
            Assert.True(token.Length > 0 && token.Split('.').Length == 3);
        }

        [Fact]
        public void Build_WithPayload()
        {
            var testtime = DateTime.UtcNow.AddHours(5).ToString(CultureInfo.InvariantCulture);
            var token = new JwtBuilder()
                .SetAlgorithm(new HMACSHA256Algorithm())
                .SetSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
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
        public void Build_WithAlgorithm_WithoutSecret_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                         .SetAlgorithm(new HMACSHA256Algorithm())
                                         .Build());
        }

        [Fact]
        public void Build_WithoutAlgorithm_WithSecret_Should_Throw_Exception()
        {
            Assert.Throws<InvalidOperationException>(() => new JwtBuilder()
                                         .SetSecret("fjhsdghflghlk")
                                         .Build());
        }
    }
}