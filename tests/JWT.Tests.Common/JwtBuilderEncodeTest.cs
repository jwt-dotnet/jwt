using System;
using JWT.Algorithms;
using JWT.Builder.Enums;
using JWT.Builder.Models;
using JWT.Serializers;
using JWT.Tests.Common;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtBuilderEncodeTest
    {
        [Fact]
        public void CreateToken()
        {
            var token = new JwtBuilder()
                .SetAlgorithm(new HMACSHA256Algorithm())
                .SetSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
                .Build();
            Assert.True(token.Length > 0 && token.Split('.').Length == 3);
        }

        [Fact]
        public void CreateTokenWithPayload()
        {
            var testtime = DateTime.UtcNow.AddHours(5).ToString();
            var token = new JwtBuilder()
                .SetAlgorithm(new HMACSHA256Algorithm())
                .SetSecret("gsdhjfkhdfjklhjklgfsdhgfbsdgfvsdvfghjdjfgb")
                .AddClaim(PublicClaimsNames.ExpirationTime, testtime)
                .Build();
            Assert.True(token.Length > 0 && token.Split('.').Length == 3);

            var decodedToken = System.Text.Encoding.UTF8.GetString(new JwtBase64UrlEncoder().Decode(token.Split('.')[1]));
            Assert.True(decodedToken.Contains("exp") && decodedToken.Contains(testtime));
        }

        [Fact]
        public void TryToCreateTokenWithoutInformaiton()
        {
            Assert.Throws<Exception>(() => new JwtBuilder().Build());
        }

        [Fact]
        public void TryToCreateTokenOnlyWithAlgorithm()
        {
            Assert.Throws<Exception>(() => new JwtBuilder().SetAlgorithm(new HMACSHA256Algorithm()).Build());
        }

        [Fact]
        public void TryToCreateTokenOnlyWithSecret()
        {
            Assert.Throws<Exception>(() => new JwtBuilder().SetSecret("fjhsdghflghlk").Build());
        }
    }
}