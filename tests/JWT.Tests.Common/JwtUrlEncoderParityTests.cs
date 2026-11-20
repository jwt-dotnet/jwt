using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    /// <summary>
    /// <see cref="JwtBase64UrlEncoder" /> lets the encoder and decoder skip intermediate arrays and strings on some targets,
    /// which must behave the same as any other <see cref="IBase64UrlEncoder" />.
    /// </summary>
    [TestClass]
    public class JwtUrlEncoderParityTests
    {
        private static readonly byte[] Key = Encoding.UTF8.GetBytes(TestData.Secret);

        // Payload sizes in steps smaller than the base64url-encoded size of a signature, to cover buffer size boundaries
        private static readonly IDictionary<string, object>[] Payloads =
            Enumerable.Range(0, 13).Select(i => CreatePayload(i * 30)).Concat([CreatePayload(1024)]).ToArray();

        private static readonly Lazy<RSA> Rsa = new Lazy<RSA>(() => CreateRsa(2048));

        private static readonly Lazy<RSA> LargeRsa = new Lazy<RSA>(() => CreateRsa(4608));

        public static IEnumerable<object[]> Algorithms =>
        [
            ["HS256"],
            ["HS384"],
            ["HS512"],
            ["RS256"],
            ["RS512 4608"],
#if NETSTANDARD2_0 || NET6_0_OR_GREATER
            ["ES256"],
            ["ES512"],
#endif
        ];

        public static IEnumerable<object[]> DeterministicAlgorithms =>
            Algorithms.Where(a => !((string)a[0]).StartsWith("ES", StringComparison.Ordinal)).Concat([["none"]]);

        [DynamicData(nameof(DeterministicAlgorithms))]
        [TestMethod]
        public void Encode_Should_Return_Same_Token_As_Custom_Url_Encoder(string algorithmName)
        {
            var algorithm = CreateAlgorithm(algorithmName);

            foreach (var payload in Payloads)
            {
                var expected = CreateEncoder(algorithm, new CustomUrlEncoder()).Encode(payload, Key);

                var actual = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(payload, Key);

                actual.Should()
                      .Be(expected, "because the default URL encoder must produce the same token");
            }
        }

        [DynamicData(nameof(Algorithms))]
        [TestMethod]
        public void Decode_Should_Return_Same_Payload_As_Custom_Url_Encoder(string algorithmName)
        {
            var algorithm = CreateAlgorithm(algorithmName);

            foreach (var payload in Payloads)
            {
                var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(payload, Key);
                var expected = CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(token, Key);

                var actual = CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(token, Key);

                actual.Should()
                      .Be(expected, "because the default URL encoder must decode the same payload");
            }
        }

        [DynamicData(nameof(Algorithms))]
        [TestMethod]
        public void Decode_Should_Throw_Same_Exception_As_Custom_Url_Encoder_When_Signature_Is_Invalid(string algorithmName)
        {
            var algorithm = CreateAlgorithm(algorithmName);
            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            var parts = token.Split('.');
            var signature = Convert.FromBase64String(Base64UrlToBase64(parts[2]));
            signature[0] ^= 1;
            var tamperedToken = $"{parts[0]}.{parts[1]}.{new JwtBase64UrlEncoder().Encode(signature)}";
            var keys = new[] { Encoding.UTF8.GetBytes(TestData.Secret2), Encoding.UTF8.GetBytes(TestData.Secret2 + TestData.Secret) };

            var expected = CatchException(() => CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(tamperedToken, keys));

            var actual = CatchException(() => CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(tamperedToken, keys));

            actual.Should()
                  .BeOfType<SignatureVerificationException>("because the tampered signature must be rejected");
            AssertSameException(actual, expected);
        }

        [DataRow("")]
        [DataRow("AB")]
        [DataRow("A")]
        [DataRow("abc!")]
        [DataRow("ab c")]
        [DataRow("ab+/")]
        [TestMethod]
        public void Decode_Should_Throw_Same_Exception_As_Custom_Url_Encoder_When_Signature_Segment_Is_Malformed(string signature)
        {
            var algorithm = CreateAlgorithm("HS256");
            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            var malformedToken = token.Substring(0, token.LastIndexOf('.') + 1) + signature;

            var expected = CatchException(() => CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(malformedToken, Key));

            var actual = CatchException(() => CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(malformedToken, Key));

            actual.Should()
                  .NotBeNull("because the malformed signature must be rejected");
            AssertSameException(actual, expected);
        }

        // HashAlgorithmName is ambiguous in the net40 test project, which polyfills it
#if NETSTANDARD2_0 || NET6_0_OR_GREATER
        [TestMethod]
        public void Encode_Should_Use_Algorithm_Created_By_Derived_HMACSHAAlgorithm()
        {
            var algorithm = new MismatchedHMACSHAAlgorithm();

            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);

            var signature = new JwtBase64UrlEncoder().Decode(token.Split('.')[2]);
            signature.Should()
                     .HaveCount(64, "because the derived algorithm creates HMAC-SHA512");
            CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(token, Key).Should()
                     .NotBeNullOrEmpty("because the derived algorithm must also be used to verify the signature");
        }
#endif

        private static IDictionary<string, object> CreatePayload(int nameLength) =>
            new Dictionary<string, object>
            {
                { "sub", "1234567890" },
                { "name", new string('x', nameLength) },
                { "exp", 4102444800 }
            };

        private static IJwtAlgorithm CreateAlgorithm(string name) =>
            name switch
            {
                "HS256" => new HMACSHA256Algorithm(),
                "HS384" => new HMACSHA384Algorithm(),
                "HS512" => new HMACSHA512Algorithm(),
                "RS256" => new RS256Algorithm(Rsa.Value, Rsa.Value),
                "RS512 4608" => new RS512Algorithm(LargeRsa.Value, LargeRsa.Value),
#if NETSTANDARD2_0 || NET6_0_OR_GREATER
                "ES256" => CreateEcdsaAlgorithm(ECCurve.NamedCurves.nistP256, key => new ES256Algorithm(key, key)),
                "ES512" => CreateEcdsaAlgorithm(ECCurve.NamedCurves.nistP521, key => new ES512Algorithm(key, key)),
#endif
                "none" => new NoneAlgorithm(),
                _ => throw new ArgumentOutOfRangeException(nameof(name))
            };

#if NETSTANDARD2_0 || NET6_0_OR_GREATER
        private static IJwtAlgorithm CreateEcdsaAlgorithm(ECCurve curve, Func<ECDsa, ECDSAAlgorithm> algFactory) =>
            algFactory(ECDsa.Create(curve));
#endif

        private static RSA CreateRsa(int keySize)
        {
            var rsa = RSA.Create();
            rsa.KeySize = keySize;
            return rsa;
        }

        private static IJwtEncoder CreateEncoder(IJwtAlgorithm algorithm, IBase64UrlEncoder urlEncoder) =>
            new JwtEncoder(algorithm, new JsonNetSerializer(), urlEncoder);

        private static IJwtDecoder CreateDecoder(IJwtAlgorithm algorithm, IBase64UrlEncoder urlEncoder)
        {
            var serializer = new JsonNetSerializer();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            return new JwtDecoder(serializer, validator, urlEncoder, algorithm);
        }

        private static Exception CatchException(Action action)
        {
            try
            {
                action();
                return null;
            }
            catch (Exception ex)
            {
                return ex;
            }
        }

        private static void AssertSameException(Exception actual, Exception expected)
        {
            expected.Should()
                    .NotBeNull("because the custom URL encoder must throw too");
            actual.Should()
                  .BeOfType(expected.GetType(), "because the default URL encoder must throw the same exception");
            actual.Message.Should()
                  .Be(expected.Message);
            if (expected is SignatureVerificationException sve)
            {
                var actualSve = (SignatureVerificationException)actual;
                actualSve.Expected.Should()
                         .Be(sve.Expected);
                actualSve.Received.Should()
                         .Be(sve.Received);
            }
        }

        private static string Base64UrlToBase64(string input)
        {
            var output = input.Replace('-', '+').Replace('_', '/');
            return output.PadRight(output.Length + (4 - output.Length % 4) % 4, '=');
        }

        private sealed class CustomUrlEncoder : IBase64UrlEncoder
        {
            private readonly JwtBase64UrlEncoder _urlEncoder = new JwtBase64UrlEncoder();

            public string Encode(byte[] input) =>
                _urlEncoder.Encode(input);

            public byte[] Decode(string input) =>
                _urlEncoder.Decode(input);
        }

#if NETSTANDARD2_0 || NET6_0_OR_GREATER
        private sealed class MismatchedHMACSHAAlgorithm : HMACSHAAlgorithm
        {
            public override string Name => nameof(JwtAlgorithmName.HS256);

            public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

            protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA512(key);
        }
#endif
    }
}
