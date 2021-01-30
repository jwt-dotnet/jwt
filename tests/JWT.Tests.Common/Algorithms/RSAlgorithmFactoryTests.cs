using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class RSAlgorithmFactoryTests
    {
        private static readonly Fixture _fixture = new Fixture();

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS256Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS256()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS256.ToString()
                }
            };
            var alg = factory.Create(context);

            alg
                .Should()
                .BeOfType<RS256Algorithm>("because Create should return an instance of RS256Algorithm when the algorithm name in the header is 'RS256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS384Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS384()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS384.ToString()
                }
            };
            var alg = factory.Create(context);

            alg
                .Should()
                .BeOfType<RS384Algorithm>("because Create should return an instance of RS384Algorithm when the algorithm name in the header is 'RS256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS512Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS512()
        {
            var publicKey = _fixture.Create<RSACryptoServiceProvider>();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS512.ToString()
                }
            };
            var alg = factory.Create(context);

            alg
                .Should()
                .BeOfType<RS512Algorithm>("because Create should return an instance of RS384Algorithm when the algorithm name in the header is 'RS256'");
        }
    }
}