#if !(NET35 || NET40 || NET46)
using System.Security.Cryptography;
using FluentAssertions;
using JWT.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class ES384AlgorithmTests
    {
        [TestMethod]
        public void Name_Should_Be_ES384()
        {
            var publicKey = ECDsa.Create();
            var alg = new ES384Algorithm(publicKey);

            alg.Name.Should()
                    .Be(JwtAlgorithmName.ES384.ToString());
        }

        [TestMethod]
        public void HashAlgorithm_Should_Be_SHA384()
        {
            var publicKey = ECDsa.Create();
            var alg = new ES384Algorithm(publicKey);

            alg.HashAlgorithm.Should()
                             .Be("SHA384");
        }
    }
}
#endif
