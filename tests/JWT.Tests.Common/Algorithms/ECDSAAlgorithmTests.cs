#if NETSTANDARD2_0 || NET5_0
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class ECDSAAlgorithmTests
    {
        [DynamicData(nameof(GetFactoryWithPublicPrivateKey), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Ctor_Should_Throw_Exception_When_PublicKey_Is_Null(Func<ECDsa, ECDsa, ECDSAAlgorithm> algFactory)
        {
            var privateKey = ECDsa.Create();

            Action action = () => algFactory(null, privateKey);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without public key");
        }

        [DynamicData(nameof(GetFactoryWithPublicPrivateKey), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Ctor_Should_Throw_Exception_When_PrivateKey_Is_Null(Func<ECDsa, ECDsa, ECDSAAlgorithm> algFactory)
        {
            var publicKey = ECDsa.Create();

            Action action = () => algFactory(publicKey, null);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without private key");
        }

        [DynamicData(nameof(GetFactoryWithPublicKey), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Sign_Should_Throw_Exception_When_PrivateKey_Is_Null(Func<ECDsa, ECDSAAlgorithm> algFactory)
        {
            var publicKey = ECDsa.Create();
            var alg = algFactory(publicKey);

            var bytesToSign = Array.Empty<byte>();

            Action action = () => alg.Sign(null, bytesToSign);

            action.Should()
                  .Throw<InvalidOperationException>("because asymmetric algorithm cannot sign data without private key");
        }

        [DynamicData(nameof(GetFactoryWithCert), DynamicDataSourceType.Method)]
        [DataTestMethod]
        public void Ctor_Should_Not_Throw_Exception_When_Certificate_Has_No_PrivateKey(Func<X509Certificate2, ECDSAAlgorithm> algFactory)
        {
            var bytes = Encoding.ASCII.GetBytes(TestData.ServerEcdsaPublicKey);
            var cert = new X509Certificate2(bytes);

            var alg = algFactory(cert);

            alg.Should()
               .NotBeNull();
        }

        private static IEnumerable<object[]> GetFactoryWithPublicKey()
        {
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(publicKey => new ES256Algorithm(publicKey)) };
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(publicKey => new ES384Algorithm(publicKey)) };
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(publicKey => new ES512Algorithm(publicKey)) };
        }

        private static IEnumerable<object[]> GetFactoryWithPublicPrivateKey()
        {
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>((publicKey, privateKey) => new ES256Algorithm(publicKey, privateKey)) };
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>((publicKey, privateKey) => new ES384Algorithm(publicKey, privateKey)) };
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>((publicKey, privateKey) => new ES512Algorithm(publicKey, privateKey)) };
        }

        private static IEnumerable<object[]> GetFactoryWithCert()
        {
            yield return new object[] { new Func<X509Certificate2, ECDSAAlgorithm>(cert => new ES256Algorithm(cert)) };
            yield return new object[] { new Func<X509Certificate2, ECDSAAlgorithm>(cert => new ES384Algorithm(cert)) };
            yield return new object[] { new Func<X509Certificate2, ECDSAAlgorithm>(cert => new ES512Algorithm(cert)) };
        }
    }
}
#endif
