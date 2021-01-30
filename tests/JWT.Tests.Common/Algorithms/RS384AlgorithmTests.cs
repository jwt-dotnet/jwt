using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class RS384AlgorithmTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Name_Should_Be_RS384()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var alg = new RS384Algorithm(publicKey);

            alg.Name
                .Should()
                .Be(JwtAlgorithmName.RS384.ToString());
        }

        [TestMethod]
        public void HashAlgorithm_Should_Be_SHA384()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var alg = new RS384Algorithm(publicKey);

            alg.HashAlgorithm
                .Should()
                .Be("SHA384");
        }
    }
}