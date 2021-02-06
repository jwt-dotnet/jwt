#if !(NET35 || NET40 || NET46)
using System.Security.Cryptography;
using FluentAssertions;
using JWT.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class ES512AlgorithmTests
    {
        [TestMethod]
        public void Name_Should_Be_ES512()
        {
            var publicKey = ECDsa.Create();
            var alg = new ES512Algorithm(publicKey);

            alg.Name.Should()
                    .Be(JwtAlgorithmName.ES512.ToString());
        }

        [TestMethod]
        public void HashAlgorithm_Should_Be_SHA512()
        {
            var publicKey = ECDsa.Create();
            var alg = new ES512Algorithm(publicKey);

            alg.HashAlgorithm.Should()
                             .Be("SHA512");
        }
    }
}
#endif
