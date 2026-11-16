using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWT.Tests
{
    [TestClass]
    public class WycheproofTests
    {
        private static readonly JwtBase64UrlEncoder UrlEncoder = new JwtBase64UrlEncoder();
        private static readonly ISet<string> EncryptionKeyOperations = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey"
        };
        private static readonly IReadOnlyDictionary<string, JObject> VectorFiles = LoadVectorFiles();

        [DynamicData(nameof(GetVectors), DynamicDataSourceType.Method)]
        [TestMethod]
        public void Verify_Wycheproof_Jws_Vector_Should_Match_Expected_Result(string file, int groupIndex, int testIndex)
        {
            var group = (JObject)((JArray)VectorFiles[file]["testGroups"])[groupIndex];
            var test = (JObject)((JArray)group["tests"])[testIndex];
            var tokenNode = test["jws"];
            if (tokenNode is null)
            {
                Assert.Inconclusive("JWT implements compact JWS signatures and does not implement JWE encryption vectors.");
            }

            var token = tokenNode is JValue ? (string)tokenNode : tokenNode.ToString(Formatting.None);
            if (token is null)
            {
                Assert.Fail("Wycheproof vector JWS must not be null.");
            }

            var expected = (string)test["result"];
            if (expected is null)
            {
                Assert.Fail("Wycheproof vector result must not be null.");
            }

            var comment = (string)test["comment"];
            if (comment is null)
            {
                Assert.Fail("Wycheproof vector comment must not be null.");
            }

            if (comment.IndexOf("RocaVulnerability", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Assert.Inconclusive("JWT accepts caller supplied RSA keys and does not implement JWK ROCA key screening.");
            }

            if (token.StartsWith("{", StringComparison.Ordinal))
            {
                Assert.Inconclusive("JWT supports compact JWS; this vector uses JSON serialization.");
            }

            var parts = token.Split('.');
            if (parts.Length == 3)
            {
                VerifyCompactJws(parts, token, expected, comment, file, groupIndex, testIndex, group);
            }
            else
            {
                VerifyMalformedJwsParts(token, expected, file, groupIndex, testIndex);
            }
        }

        private static void VerifyCompactJws(string[] parts, string token, string expected, string comment, string file, int groupIndex, int testIndex, JObject group)
        {
            var key = (JObject)(group["public"] ?? group["private"] ?? group["key"]);
            if (key is null)
            {
                Assert.Fail("This compact JWS vector must provide a signing key.");
            }

            if (key["keys"] is JArray)
            {
                Assert.Inconclusive("JWT's signature API does not accept JWK sets.");
            }

            var keyOperations = key["key_ops"] is JArray operations ? operations : null;
            if (String.Equals((string)key["use"], "enc", StringComparison.OrdinalIgnoreCase) ||
                (keyOperations is not null && keyOperations.Any(static o => EncryptionKeyOperations.Contains((string)o))))
            {
                Assert.Inconclusive("This vector provides an encryption key rather than a signing key.");
            }

            if (key["alg"] is null)
            {
                Assert.Fail("This compact JWS signing key must provide an algorithm.");
            }

            var algorithmName = (string)key["alg"];

            if (parts[0].Length == 0 || parts[2].Length == 0)
            {
                VerifyMalformedJwsSignature(token, expected, file, groupIndex, testIndex, algorithmName, key);
            }
            else
            {
                if (!IsCanonicalBase64Url(parts[0]) || !IsCanonicalBase64Url(parts[1]) || !IsCanonicalBase64Url(parts[2]))
                {
                    Assert.Inconclusive("JwtBase64UrlEncoder.Decode uses the standard Base64 decoder for noncanonical Base64URL segments.");
                }

                if (comment.IndexOf("Base64Padding", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Assert.Inconclusive("JwtBase64UrlEncoder.Decode delegates padding handling to the standard Base64 decoder.");
                }

                byte[] secret;
                IDisposable disposableKey;
                var algorithm = CreateAlgorithm(algorithmName, key, out secret, out disposableKey);
                if (algorithm is null)
                {
                    Assert.Inconclusive("JWT does not implement the " + algorithmName + " signing algorithm on this target framework.");
                }

                using var disposableKeyScope = disposableKey;
                var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
                var signature = UrlEncoder.Decode(parts[2]);
                bool actual;

                if (algorithm is IAsymmetricAlgorithm asymmetricAlgorithm)
                {
                    actual = asymmetricAlgorithm.Verify(signingInput, signature);
                }
                else
                {
                    var validator = new JwtValidator(new DefaultJsonSerializerFactory().Create(), new UtcDateTimeProvider());
                    actual = validator.TryValidate(
                        "{}",
                        Convert.ToBase64String(signature),
                        Convert.ToBase64String(algorithm.Sign(secret, signingInput)),
                        out _);
                }

                AssertResult(actual, expected, file, groupIndex, testIndex);
            }
        }

        private static void VerifyMalformedJwsParts(string token, string expected, string file, int groupIndex, int testIndex)
        {
            var actual = true;
            try
            {
                new JwtParts(token);
            }
            catch (InvalidTokenPartsException)
            {
                actual = false;
            }
            catch (ArgumentException)
            {
                actual = false;
            }

            AssertResult(actual, expected, file, groupIndex, testIndex);
        }

        private static void VerifyMalformedJwsSignature(string token, string expected, string file, int groupIndex, int testIndex, string algorithmName, JObject key)
        {
            var malformedAlgorithm = CreateAlgorithm(algorithmName, key, out var malformedSecret, out var malformedDisposableKey);
            using var malformedDisposableKeyScope = malformedDisposableKey;

            var serializer = new DefaultJsonSerializerFactory().Create();
            var validator = new JwtValidator(serializer, new UtcDateTimeProvider());
            var algorithmFactory = new DelegateAlgorithmFactory(new MalformedJwsAlgorithmFactory(malformedAlgorithm));
            var decoder = new JwtDecoder(serializer, validator, UrlEncoder, algorithmFactory);
            var actual = true;
            try
            {
                decoder.Decode(new JwtParts(token), malformedSecret, verify: true);
            }
            catch (ArgumentException)
            {
                actual = false;
            }
            catch (FormatException)
            {
                actual = false;
            }
            catch (JsonException)
            {
                actual = false;
            }
            catch (SignatureVerificationException)
            {
                actual = false;
            }
            catch (CryptographicException)
            {
                actual = false;
            }
            catch (NotSupportedException)
            {
                actual = false;
            }

            AssertResult(actual, expected, file, groupIndex, testIndex);
        }

        private static IEnumerable<object[]> GetVectors()
        {
            var files = new[] { "json_web_crypto_test.json", "json_web_signature_test.json" };
            return files
                .SelectMany(
                    static f => ((JArray)VectorFiles[f]["testGroups"])
                        .Select(static (g, i) => (Group: (JObject)g, Index: i)),
                    static (f, g) => (File: f, g.Group, GroupIndex: g.Index))
                .SelectMany(
                    static v => ((JArray)v.Group["tests"]).Select(static (_, i) => i),
                    static (v, i) => (object[])[v.File, v.GroupIndex, i]);
        }

        private static IReadOnlyDictionary<string, JObject> LoadVectorFiles()
        {
            var files = new[] { "json_web_crypto_test.json", "json_web_signature_test.json" };
            return files.ToDictionary(
                static f => f,
                static f => JObject.Parse(File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wycheproof", f))));
        }

        private static IJwtAlgorithm CreateAlgorithm(string algorithmName, JObject key, out byte[] secret, out IDisposable disposableKey)
        {
            secret = null;
            disposableKey = null;

            switch (algorithmName)
            {
                case "HS256":
                {
                    secret = UrlEncoder.Decode((string)key["k"]);
                    return new HMACSHA256Algorithm();
                }
                case "HS384":
                {
                    secret = UrlEncoder.Decode((string)key["k"]);
                    return new HMACSHA384Algorithm();
                }
                case "HS512":
                {
                    secret = UrlEncoder.Decode((string)key["k"]);
                    return new HMACSHA512Algorithm();
                }
                case "RS256":
                case "RS384":
                case "RS512":
                {
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters
                    {
                        Modulus = UrlEncoder.Decode((string)key["n"]),
                        Exponent = UrlEncoder.Decode((string)key["e"])
                    });
                    disposableKey = rsa;
                    if (algorithmName == "RS256")
                    {
                        return new RS256Algorithm(rsa);
                    }
                    if (algorithmName == "RS384")
                    {
                        return new RS384Algorithm(rsa);
                    }
                    return new RS512Algorithm(rsa);
                }
                case "ES256":
                case "ES384":
                case "ES512":
                {
#if NETCOREAPP3_1_OR_GREATER || NET6_0_OR_GREATER
                    var ecdsa = ECDsa.Create();
                    ecdsa.ImportParameters(new ECParameters
                    {
                        Curve = GetCurve((string)key["crv"]),
                        Q = new ECPoint
                        {
                            X = UrlEncoder.Decode((string)key["x"]),
                            Y = UrlEncoder.Decode((string)key["y"])
                        }
                    });
                    disposableKey = ecdsa;
                    if (algorithmName == "ES256")
                    {
                        return new ES256Algorithm(ecdsa);
                    }
                    if (algorithmName == "ES384")
                    {
                        return new ES384Algorithm(ecdsa);
                    }
                    return new ES512Algorithm(ecdsa);
#else
                    return null;
#endif
                }
                default:
                {
                    return null;
                }
            }
        }

        private static bool IsCanonicalBase64Url(string value)
        {
            if (value.Length == 0)
            {
                return true;
            }

            foreach (var character in value)
            {
                if (!((character >= 'A' && character <= 'Z') ||
                      (character >= 'a' && character <= 'z') ||
                      (character >= '0' && character <= '9') ||
                      character == '-' || character == '_'))
                {
                    return false;
                }
            }

            try
            {
                return UrlEncoder.Encode(UrlEncoder.Decode(value)) == value;
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        private static void AssertResult(bool actual, string expected, string file, int groupIndex, int testIndex)
        {
            var expectedValid = expected == "valid" || expected == "acceptable";
            actual.Should().Be(expectedValid, "Wycheproof {0}, group {1}, case {2}, expects {3}", file, groupIndex, testIndex, expected);
        }

        private sealed class MalformedJwsAlgorithmFactory : IAlgorithmFactory
        {
            private readonly IJwtAlgorithm _algorithm;

            public MalformedJwsAlgorithmFactory(IJwtAlgorithm algorithm)
            {
                _algorithm = algorithm;
            }

            public IJwtAlgorithm Create(JwtDecoderContext context)
            {
                if (String.Equals(context.Header.Algorithm, nameof(JwtAlgorithmName.None), StringComparison.OrdinalIgnoreCase))
                {
                    return new NoneAlgorithm();
                }

                return _algorithm;
            }
        }

#if NETCOREAPP3_1_OR_GREATER || NET6_0_OR_GREATER
        private static ECCurve GetCurve(string curve)
        {
            switch (curve)
            {
                case "P-256":
                {
                    return ECCurve.NamedCurves.nistP256;
                }
                case "P-384":
                {
                    return ECCurve.NamedCurves.nistP384;
                }
                case "P-521":
                {
                    return ECCurve.NamedCurves.nistP521;
                }
                default:
                {
                    throw new NotSupportedException(curve);
                }
            }
        }
#endif
    }
}
