#if NETSTANDARD2_0 || NET6_0_OR_GREATER
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
        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PublicKey_Is_Null(Func<ECDsa, ECDsa, ECDSAAlgorithm> algFactory, int keySize)
        {
            using var privateKey = CreateKey(keySize);

            Action action = () => algFactory(null, privateKey);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without public key");
        }

        [DynamicData(nameof(GetFactoryWithPublicPrivateKey), DynamicDataSourceType.Method)]
        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PrivateKey_Is_Null(Func<ECDsa, ECDsa, ECDSAAlgorithm> algFactory, int keySize)
        {
            using var publicKey = CreateKey(keySize);

            Action action = () => algFactory(publicKey, null);

            action.Should()
                  .Throw<ArgumentNullException>("because asymmetric algorithm cannot be constructed without private key");
        }

        [DynamicData(nameof(GetFactoryWithPublicKey), DynamicDataSourceType.Method)]
        [TestMethod]
        public void Sign_Should_Throw_Exception_When_PrivateKey_Is_Null(Func<ECDsa, ECDSAAlgorithm> algFactory, int keySize)
        {
            using var publicKey = CreateKey(keySize);
            var alg = algFactory(publicKey);

            var bytesToSign = Array.Empty<byte>();

            Action action = () => alg.Sign(null, bytesToSign);

            action.Should()
                  .Throw<InvalidOperationException>("because asymmetric algorithm cannot sign data without private key");
        }

        [TestMethod]
        public void Ctor_Should_Not_Throw_Exception_When_Certificate_Has_No_PrivateKey()
        {
            var cert = TestData.CertificateWithPublicKeyEcdsa;

            var alg = new ES256Algorithm(cert);

            alg.Should()
               .NotBeNull();
        }

        [DynamicData(nameof(GetFactoryWithPublicPrivateKey), DynamicDataSourceType.Method)]
        [TestMethod]
        public void Verify_Should_Return_True_When_Key_Curve_Matches_Algorithm(Func<ECDsa, ECDsa, ECDSAAlgorithm> algFactory, int keySize)
        {
            using var key = CreateKey(keySize);
            var alg = algFactory(key, key);

            var bytesToSign = Encoding.UTF8.GetBytes("test");
            var signature = alg.Sign(null, bytesToSign);

            alg.Verify(bytesToSign, signature)
               .Should()
               .BeTrue("because a key on the curve required by the algorithm must sign and verify the data");
        }

        [DynamicData(nameof(GetFactoryWithPublicKeyAndMismatchedKeySize), DynamicDataSourceType.Method)]
        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PublicKey_Curve_Does_Not_Match_Algorithm(Func<ECDsa, ECDSAAlgorithm> algFactory, int keySize)
        {
            using var publicKey = CreateKey(keySize);

            Action action = () => algFactory(publicKey);

            action.Should()
                  .Throw<ArgumentException>("because the public key must be on the curve required by the algorithm")
                  .WithParameterName("publicKey");
        }

        [DynamicData(nameof(GetFactoryWithPublicPrivateKeyAndMismatchedKeySize), DynamicDataSourceType.Method)]
        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_PublicPrivateKey_Curve_Does_Not_Match_Algorithm(Func<ECDsa, ECDsa, ECDSAAlgorithm> algFactory, int publicKeySize, int privateKeySize, string paramName)
        {
            using var publicKey = CreateKey(publicKeySize);
            using var privateKey = CreateKey(privateKeySize);

            Action action = () => algFactory(publicKey, privateKey);

            action.Should()
                  .Throw<ArgumentException>("because the keys must be on the curve required by the algorithm")
                  .WithParameterName(paramName);
        }

        [DynamicData(nameof(GetFactoryWithMismatchedCert), DynamicDataSourceType.Method)]
        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_Certificate_Curve_Does_Not_Match_Algorithm(Func<X509Certificate2, ECDSAAlgorithm> algFactory)
        {
            var cert = TestData.CertificateWithPublicKeyEcdsa;

            Action action = () => algFactory(cert);

            action.Should()
                  .Throw<ArgumentException>("because the certificate key must be on the curve required by the algorithm")
                  .WithParameterName("cert");
        }

        private static ECDsa CreateKey(int keySize) =>
            ECDsa.Create(keySize switch
            {
                256 => ECCurve.NamedCurves.nistP256,
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentOutOfRangeException(nameof(keySize))
            });

        private static IEnumerable<object[]> GetFactoryWithPublicKey()
        {
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(static publicKey => new ES256Algorithm(publicKey)), 256 };
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(static publicKey => new ES384Algorithm(publicKey)), 384 };
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(static publicKey => new ES512Algorithm(publicKey)), 521 };
        }

        private static IEnumerable<object[]> GetFactoryWithPublicPrivateKey()
        {
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>(static (publicKey, privateKey) => new ES256Algorithm(publicKey, privateKey)), 256 };
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>(static (publicKey, privateKey) => new ES384Algorithm(publicKey, privateKey)), 384 };
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>(static (publicKey, privateKey) => new ES512Algorithm(publicKey, privateKey)), 521 };
        }

        private static IEnumerable<object[]> GetFactoryWithPublicKeyAndMismatchedKeySize()
        {
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(static publicKey => new ES256Algorithm(publicKey)), 384 };
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(static publicKey => new ES384Algorithm(publicKey)), 521 };
            yield return new object[] { new Func<ECDsa, ECDSAAlgorithm>(static publicKey => new ES512Algorithm(publicKey)), 256 };
        }

        private static IEnumerable<object[]> GetFactoryWithPublicPrivateKeyAndMismatchedKeySize()
        {
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>(static (publicKey, privateKey) => new ES256Algorithm(publicKey, privateKey)), 521, 256, "publicKey" };
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>(static (publicKey, privateKey) => new ES384Algorithm(publicKey, privateKey)), 384, 256, "privateKey" };
            yield return new object[] { new Func<ECDsa, ECDsa, ECDSAAlgorithm>(static (publicKey, privateKey) => new ES512Algorithm(publicKey, privateKey)), 256, 256, "publicKey" };
        }

        private static IEnumerable<object[]> GetFactoryWithMismatchedCert()
        {
            yield return new object[] { new Func<X509Certificate2, ECDSAAlgorithm>(static cert => new ES384Algorithm(cert)) };
            yield return new object[] { new Func<X509Certificate2, ECDSAAlgorithm>(static cert => new ES512Algorithm(cert)) };
        }
    }
}
#endif
