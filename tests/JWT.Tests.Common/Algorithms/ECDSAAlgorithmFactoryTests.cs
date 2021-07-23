using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class ECDSAAlgorithmFactoryTests
    {
#if NETSTANDARD2_0 || NET5_0
        [TestMethod]
        public void Create_Should_Return_Instance_Of_ES256Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_ES256_And_Targeting_NetStandard20()
        {
            var publicKey = ECDsa.Create();
            var factory = new ECDSAAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.ES256.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<ES256Algorithm>("because Create should return an instance of ES256Algorithm when the algorithm name in the header is 'ES256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_ES384Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_ES384_And_Targeting_NetStandard20()
        {
            var publicKey = ECDsa.Create();
            var factory = new ECDSAAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.ES384.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<ES384Algorithm>("because Create should return an instance of ES384Algorithm when the algorithm name in the header is 'ES384'");
        }
#endif
    }
}
