using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

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
                Enumerable.Range(0, 13)
                          .Select(static i => CreatePayload(i * 30))
                          .Concat([CreatePayload(1024)])
                          .ToArray();

        private static readonly ConcurrentDictionary<int, RSA> RsaKeys = new ConcurrentDictionary<int, RSA>();

        [DynamicData(nameof(GetDeterministicAlgorithms))]
        [TestMethod]
        public void Encode_Should_Return_Same_Token_As_Custom_Url_Encoder(JwtAlgorithmName algorithmName, int? keySize)
        {
            var algorithm = CreateAlgorithm(algorithmName, keySize);

            foreach (var payload in Payloads)
            {
                var expected = CreateEncoder(algorithm, new CustomUrlEncoder()).Encode(payload, Key);

                var actual = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(payload, Key);

                actual.Should()
                      .Be(expected, "because the default URL encoder must produce the same token");
            }
        }

        [DynamicData(nameof(GetAlgorithms))]
        [TestMethod]
        public void Decode_Should_Return_Same_Payload_As_Custom_Url_Encoder(JwtAlgorithmName algorithmName, int? keySize)
        {
            var algorithm = CreateAlgorithm(algorithmName, keySize);

            foreach (var payload in Payloads)
            {
                var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(payload, Key);
                var expected = CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(token, Key);

                var actual = CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(token, Key);

                actual.Should()
                      .Be(expected, "because the default URL encoder must decode the same payload");
            }
        }

        [DynamicData(nameof(GetAlgorithms))]
        [TestMethod]
        public void Decode_Should_Throw_Same_Exception_As_Custom_Url_Encoder_When_Signature_Is_Invalid(JwtAlgorithmName algorithmName, int? keySize)
        {
            var algorithm = CreateAlgorithm(algorithmName, keySize);
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
            var algorithm = CreateAlgorithm(JwtAlgorithmName.HS256);
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

        [DataRow(0, "", true)]
        [DataRow(0, "A", true)]
        [DataRow(0, "abc!", false)]
        [DataRow(0, "ab c", true)]
        [DataRow(1, "", false)]
        [DataRow(1, "A", false)]
        [DataRow(1, "abc!", true)]
        [DataRow(1, "ab\tc", true)]
        [DataRow(1, "ab+/", true)]
        [TestMethod]
        public void Decode_Should_Throw_Same_Exception_As_Custom_Url_Encoder_When_Header_Or_Payload_Is_Malformed(int partIndex, string part, bool verify)
        {
            var algorithm = CreateAlgorithm(JwtAlgorithmName.HS256);
            var parts = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key).Split('.');
            parts[partIndex] = part;
            var malformedToken = String.Join(".", parts);

            var expected = CatchException(() => CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(malformedToken, Key, verify));

            var actual = CatchException(() => CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(malformedToken, Key, verify));

            actual.Should()
                  .NotBeNull("because the malformed segment must be rejected");
            AssertSameException(actual, expected);
        }

        [DataRow(1)]
        [DataRow(2)]
        [DataRow(4)]
        [TestMethod]
        public void Decode_Should_Throw_Same_Exception_As_Custom_Url_Encoder_When_Segment_Count_Is_Wrong(int segmentCount)
        {
            var algorithm = CreateAlgorithm(JwtAlgorithmName.HS256);
            var parts = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key).Split('.');
            var malformedToken = String.Join(".", Enumerable.Range(0, segmentCount).Select(i => parts[i % parts.Length]));

            var expected = CatchException(() => CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(malformedToken, Key));

            var actual = CatchException(() => CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(malformedToken, Key));

            actual.Should()
                  .BeOfType<InvalidTokenPartsException>("because a token must have exactly three segments");
            AssertSameException(actual, expected);
        }

        [DynamicData(nameof(GetAlgorithms))]
        [TestMethod]
        public void Decode_Should_Throw_Same_Exception_As_Custom_Url_Encoder_When_Signature_Is_Truncated(JwtAlgorithmName algorithmName, int? keySize)
        {
            var algorithm = CreateAlgorithm(algorithmName, keySize);
            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            var parts = token.Split('.');
            var signature = Convert.FromBase64String(Base64UrlToBase64(parts[2]));
            var truncatedToken = $"{parts[0]}.{parts[1]}.{new JwtBase64UrlEncoder().Encode(signature.Take(signature.Length - 1).ToArray())}";

            var expected = CatchException(() => CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(truncatedToken, Key));

            var actual = CatchException(() => CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(truncatedToken, Key));

            actual.Should()
                  .NotBeNull("because the truncated signature must be rejected");
            AssertSameException(actual, expected);
        }

        [DynamicData(nameof(GetAlgorithms))]
        [TestMethod]
        public void Decode_Should_Throw_Same_Exception_As_Custom_Url_Encoder_When_Token_Is_Expired(JwtAlgorithmName algorithmName, int? keySize)
        {
            var algorithm = CreateAlgorithm(algorithmName, keySize);
            var payload = CreatePayload(10);
            payload["exp"] = 1;
            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(payload, Key);

            var expected = CatchException(() => CreateDecoder(algorithm, new CustomUrlEncoder()).Decode(token, Key));

            var actual = CatchException(() => CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(token, Key));

            actual.Should()
                  .BeOfType<TokenExpiredException>("because the token has expired");
            AssertSameException(actual, expected);
        }

        [TestMethod]
        public void Encode_Should_Use_Custom_Url_Encoder()
        {
            var urlEncoder = new CustomUrlEncoder();

            CreateEncoder(CreateAlgorithm(JwtAlgorithmName.HS256), urlEncoder).Encode(TestData.DictionaryPayload, Key);

            urlEncoder.EncodeCount.Should()
                      .Be(3, "because the custom URL encoder must encode the header, the payload and the signature");
        }

        [DataRow(JwtAlgorithmName.HS256)]
        [DataRow(JwtAlgorithmName.RS256)]
        [TestMethod]
        public void Decode_Should_Use_Custom_Url_Encoder(JwtAlgorithmName algorithmName)
        {
            var algorithm = CreateAlgorithm(algorithmName);
            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            var urlEncoder = new CustomUrlEncoder();

            CreateDecoder(algorithm, urlEncoder).Decode(token, Key);

            urlEncoder.DecodedSegments.Should()
                      .Contain(token.Split('.'), "because the custom URL encoder must decode the header, the payload and the signature");
        }

        [TestMethod]
        public void Decode_Should_Use_Custom_Validator_For_Symmetric_Algorithm()
        {
            var algorithm = CreateAlgorithm(JwtAlgorithmName.HS256);
            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            var validator = new Mock<IJwtValidator>();

            new JwtDecoder(new JsonNetSerializer(), validator.Object, new JwtBase64UrlEncoder(), algorithm).Decode(token, Key);

            validator.Verify(static v => v.Validate(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string[]>()), Times.Once());
        }

        [TestMethod]
        public void Decode_Should_Use_Custom_Validator_For_Asymmetric_Algorithm()
        {
            var algorithm = CreateAlgorithm(JwtAlgorithmName.RS256);
            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            var validator = new Mock<IJwtValidator>();

            new JwtDecoder(new JsonNetSerializer(), validator.Object, new JwtBase64UrlEncoder(), algorithm).Decode(token, Key);

            validator.Verify(static v => v.Validate(It.IsAny<string>(), It.IsAny<IAsymmetricAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<byte[]>()), Times.Once());
        }

        // HashAlgorithmName is ambiguous in the net40 test project, which polyfills it
#if NETSTANDARD2_0 || NET6_0_OR_GREATER
        [TestMethod]
        public void Encode_And_Decode_Should_Use_Derived_RSAlgorithm()
        {
            var algorithm = new RecordingRSAlgorithm(GetRsa(2048));

            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(token, Key);

            algorithm.SignCount.Should()
                     .Be(1, "because the derived algorithm must sign the token");
            algorithm.VerifyCount.Should()
                     .Be(1, "because the derived algorithm must verify the token");
        }

        [TestMethod]
        public void Encode_And_Decode_Should_Use_Derived_ECDSAAlgorithm()
        {
            var algorithm = new RecordingECDSAAlgorithm(ECDsa.Create(ECCurve.NamedCurves.nistP256));

            var token = CreateEncoder(algorithm, new JwtBase64UrlEncoder()).Encode(TestData.DictionaryPayload, Key);
            CreateDecoder(algorithm, new JwtBase64UrlEncoder()).Decode(token, Key);

            algorithm.SignCount.Should()
                     .Be(1, "because the derived algorithm must sign the token");
            algorithm.VerifyCount.Should()
                     .Be(1, "because the derived algorithm must verify the token");
        }
#endif

        // The key size is the RSA modulus or the ECDSA curve in bits. HMAC uses Key and none has no key, so theirs is null.
        private static IEnumerable<object[]> GetAlgorithms()
        {
            yield return [JwtAlgorithmName.HS256, null];
            yield return [JwtAlgorithmName.HS384, null];
            yield return [JwtAlgorithmName.HS512, null];
            yield return [JwtAlgorithmName.RS256, 2048];
            yield return [JwtAlgorithmName.RS384, 2048];
            yield return [JwtAlgorithmName.RS512, 2048];
            yield return [JwtAlgorithmName.RS1024, 2048];
            yield return [JwtAlgorithmName.RS2048, 2048];
            yield return [JwtAlgorithmName.RS4096, 2048];
            // The signature is longer than the encoder's and validator's stack buffers
            yield return [JwtAlgorithmName.RS512, 4608];
#if NETSTANDARD2_0 || NET6_0_OR_GREATER
            yield return [JwtAlgorithmName.ES256, 256];
            yield return [JwtAlgorithmName.ES384, 384];
            yield return [JwtAlgorithmName.ES512, 521];
#endif
        }

        // ECDSA signatures are randomized, so tokens can't be compared
        private static IEnumerable<object[]> GetDeterministicAlgorithms()
        {
            foreach (var algorithm in GetAlgorithms())
            {
                if ((JwtAlgorithmName)algorithm[0] is not (JwtAlgorithmName.ES256 or JwtAlgorithmName.ES384 or JwtAlgorithmName.ES512))
                    yield return algorithm;
            }
            yield return [JwtAlgorithmName.None, null];
        }

        private static IDictionary<string, object> CreatePayload(int nameLength) =>
            new Dictionary<string, object>
            {
                { "sub", "1234567890" },
                { "name", new string('x', nameLength) },
                { "exp", 4102444800 }
            };

        private static IJwtAlgorithm CreateAlgorithm(JwtAlgorithmName algorithm, int? keySize = null)
        {
            IAlgorithmFactory factory = algorithm switch
            {
                JwtAlgorithmName.HS256 or JwtAlgorithmName.HS384 or JwtAlgorithmName.HS512 =>
                    new HMACSHAAlgorithmFactory(),
                JwtAlgorithmName.RS256 or JwtAlgorithmName.RS384 or JwtAlgorithmName.RS512 or
                JwtAlgorithmName.RS1024 or JwtAlgorithmName.RS2048 or JwtAlgorithmName.RS4096 =>
                    new RSAlgorithmFactory(GetRsa(keySize ?? 2048), GetRsa(keySize ?? 2048)),
#if NETSTANDARD2_0 || NET6_0_OR_GREATER
                JwtAlgorithmName.ES256 or JwtAlgorithmName.ES384 or JwtAlgorithmName.ES512 =>
                    CreateEcdsaAlgorithmFactory(keySize ?? throw new ArgumentNullException(nameof(keySize))),
#endif
                JwtAlgorithmName.None =>
                    new GenericAlgorithmFactory<NoneAlgorithm>(),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
            };
            return factory.Create(new JwtDecoderContext { Header = new JwtHeader { Algorithm = algorithm.ToString() } });
        }

#if NETSTANDARD2_0 || NET6_0_OR_GREATER
        private static ECDSAAlgorithmFactory CreateEcdsaAlgorithmFactory(int keySize)
        {
            var key = ECDsa.Create(keySize switch
            {
                256 => ECCurve.NamedCurves.nistP256,
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentOutOfRangeException(nameof(keySize))
            });
            return new ECDSAAlgorithmFactory(key, key);
        }
#endif

        private static RSA GetRsa(int keySize) =>
            RsaKeys.GetOrAdd(keySize, static size => CreateRsa(size));

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

            public int EncodeCount { get; private set; }

            public List<string> DecodedSegments { get; } = new List<string>();

            public string Encode(byte[] input)
            {
                this.EncodeCount++;
                return _urlEncoder.Encode(input);
            }

            public byte[] Decode(string input)
            {
                this.DecodedSegments.Add(input);
                return _urlEncoder.Decode(input);
            }
        }

#if NETSTANDARD2_0 || NET6_0_OR_GREATER
        private sealed class RecordingRSAlgorithm : RSAlgorithm
        {
            public RecordingRSAlgorithm(RSA key)
                : base(key, key)
            {
            }

            public int SignCount { get; private set; }

            public int VerifyCount { get; private set; }

            public override string Name => nameof(JwtAlgorithmName.RS256);

            public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

            protected override byte[] SignData(byte[] bytesToSign)
            {
                this.SignCount++;
                return base.SignData(bytesToSign);
            }

            protected override bool VerifyData(byte[] bytesToSign, byte[] signature)
            {
                this.VerifyCount++;
                return base.VerifyData(bytesToSign, signature);
            }
        }

        private sealed class RecordingECDSAAlgorithm : ECDSAAlgorithm
        {
            public RecordingECDSAAlgorithm(ECDsa key)
                : base(key, key)
            {
            }

            public int SignCount { get; private set; }

            public int VerifyCount { get; private set; }

            public override string Name => nameof(JwtAlgorithmName.ES256);

            public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

            protected override int RequiredKeySize => 256;

            protected override byte[] SignData(byte[] bytesToSign)
            {
                this.SignCount++;
                return base.SignData(bytesToSign);
            }

            protected override bool VerifyData(byte[] bytesToSign, byte[] signature)
            {
                this.VerifyCount++;
                return base.VerifyData(bytesToSign, signature);
            }
        }

        private sealed class MismatchedHMACSHAAlgorithm : HMACSHAAlgorithm
        {
            public override string Name => nameof(JwtAlgorithmName.HS256);

            public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

            protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA512(key);
        }
#endif
    }
}
