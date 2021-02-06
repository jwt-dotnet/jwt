using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class ECDSAAlgorithmFactoryTests
    {
#if !(NET35 || NET40 || NET46)
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
        public void Create_Should_Return_Instance_Of_ECDSA384Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_ES384_And_Targeting_NetStandard20()
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
                .BeOfType<ECDSA384Algorithm>("because Create should return an instance of ECDSA384Algorithm when the algorithm name in the header is 'ES384'");
        }
#else
        [TestMethod]
        public void Create_Should_Throw_NotImplementedException_When_Not_Targeting_NetStandard20()
        {
            Func<X509Certificate2> certFactory = () => new X509Certificate2();
            var factory = new ECDSAAlgorithmFactory(certFactory);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.ES256.ToString()
                }
            };

            factory.Invoking(f => f.Create(context))
                .Should().Throw<NotImplementedException>("because ECDSA algorithms are only supported when targeting .NET Standard 2.0");
        }
#endif
    }
}
