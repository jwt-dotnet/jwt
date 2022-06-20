using System.Security.Cryptography;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class RSAlgorithmFactoryTests
    {
        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS256Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS256()
        {
            var publicKey = new RSACryptoServiceProvider();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS256.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<RS256Algorithm>("because Create should return an instance of RS256Algorithm when the algorithm name in the header is 'RS256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS384Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS384()
        {
            var publicKey = new RSACryptoServiceProvider();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS384.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<RS384Algorithm>("because Create should return an instance of RS384Algorithm when the algorithm name in the header is 'RS256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS512Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS512()
        {
            var publicKey = new RSACryptoServiceProvider();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS512.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<RS512Algorithm>("because Create should return an instance of RS384Algorithm when the algorithm name in the header is 'RS256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS1024Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS1024()
        {
            var publicKey = new RSACryptoServiceProvider();
            
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS1024.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<RS1024Algorithm>("because Create should return an instance of RS384Algorithm when the algorithm name in the header is 'RS256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS2048Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS2048()
        {
            var publicKey = new RSACryptoServiceProvider();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS2048.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<RS2048Algorithm>("because Create should return an instance of RS384Algorithm when the algorithm name in the header is 'RS256'");
        }

        [TestMethod]
        public void Create_Should_Return_Instance_Of_RS4096Algorithm_When_Algorithm_Specified_In_Jwt_Header_Is_RS4096()
        {
            var publicKey = new RSACryptoServiceProvider();
            var factory = new RSAlgorithmFactory(publicKey);
            var context = new JwtDecoderContext
            {
                Header = new JwtHeader
                {
                    Algorithm = JwtAlgorithmName.RS4096.ToString()
                }
            };
            var alg = factory.Create(context);

            alg.Should()
               .BeOfType<RS4096Algorithm>("because Create should return an instance of RS384Algorithm when the algorithm name in the header is 'RS256'");
        }
    }
}
