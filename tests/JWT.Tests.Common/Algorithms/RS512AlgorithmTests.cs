using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class RS512AlgorithmTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Name_Should_Be_RS512()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var alg = new RS512Algorithm(publicKey);

            alg.Name.Should()
                    .Be(JwtAlgorithmName.RS512.ToString());
        }

        [TestMethod]
        public void HashAlgorithm_Should_Be_SHA512()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var alg = new RS512Algorithm(publicKey);

            alg.HashAlgorithm.Should()
                             .Be("SHA512");
        }
    }
}
