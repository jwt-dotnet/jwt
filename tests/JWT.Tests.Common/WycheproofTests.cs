using System;
using System.Collections.Generic;
using System.IO;
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
        private static readonly Dictionary<string, JObject> VectorFiles = LoadVectorFiles();

        [DataTestMethod]
        [DynamicData(nameof(GetVectors), DynamicDataSourceType.Method)]
        public void Verify_Wycheproof_Jws_Vector(string file, int groupIndex, int testIndex)
        {
            var group = (JObject)((JArray)VectorFiles[file]["testGroups"])[groupIndex];
            var test = (JObject)((JArray)group["tests"])[testIndex];
            var key = (JObject)(group["public"] ?? group["private"] ?? group["key"]);
            var algorithmName = key == null ? String.Empty : (string)key["alg"] ?? String.Empty;
            var tokenNode = test["jws"];
            if (tokenNode == null)
                Assert.Inconclusive("JWT implements compact JWS signatures and does not implement JWE encryption vectors.");

            var token = tokenNode is JValue ? (string)tokenNode : tokenNode?.ToString(Formatting.None);
            var expected = (string)test["result"] ?? String.Empty;
            var comment = (string)test["comment"] ?? String.Empty;

            if (String.IsNullOrEmpty(algorithmName))
                Assert.Inconclusive("This vector has no signing algorithm key for the JWT signature API.");

            if (comment.IndexOf("RocaVulnerability", StringComparison.OrdinalIgnoreCase) >= 0)
                Assert.Inconclusive("JWT accepts caller supplied RSA keys and does not implement JWK ROCA key screening.");

            if (token.StartsWith("{", StringComparison.Ordinal))
                Assert.Inconclusive("JWT supports compact JWS; this vector uses JSON serialization.");

            var parts = token.Split('.');
            if (parts.Length != 3)
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
                return;
            }

            if (parts[0].Length == 0 || parts[2].Length == 0)
            {
                var actual = true;
                try
                {
                    UrlEncoder.Decode(parts[0].Length == 0 ? parts[0] : parts[2]);
                }
                catch (ArgumentException)
                {
                    actual = false;
                }

                AssertResult(actual, expected, file, groupIndex, testIndex);
                return;
            }

            if (!IsCanonicalBase64Url(parts[0]) || !IsCanonicalBase64Url(parts[1]) || !IsCanonicalBase64Url(parts[2]))
                Assert.Inconclusive("JwtBase64UrlEncoder.Decode uses the standard Base64 decoder for noncanonical Base64URL segments.");

            if (comment.IndexOf("Base64Padding", StringComparison.OrdinalIgnoreCase) >= 0)
                Assert.Inconclusive("JwtBase64UrlEncoder.Decode delegates padding handling to the standard Base64 decoder.");

            byte[] secret;
            IDisposable disposableKey;
            var algorithm = CreateAlgorithm(algorithmName, key, out secret, out disposableKey);
            if (algorithm == null)
                Assert.Inconclusive("JWT does not implement the " + algorithmName + " signing algorithm on this target framework.");

            try
            {
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
            finally
            {
                if (disposableKey != null)
                    disposableKey.Dispose();
            }
        }

        private static IEnumerable<object[]> GetVectors()
        {
            foreach (var file in new[] { "json_web_crypto_test.json", "json_web_signature_test.json" })
            {
                var groups = (JArray)VectorFiles[file]["testGroups"];

                for (var groupIndex = 0; groupIndex < groups.Count; groupIndex++)
                {
                    var tests = (JArray)((JObject)groups[groupIndex])["tests"];

                    for (var testIndex = 0; testIndex < tests.Count; testIndex++)
                    {
                        yield return new object[] { file, groupIndex, testIndex };
                    }
                }
            }
        }

        private static Dictionary<string, JObject> LoadVectorFiles()
        {
            var vectorFiles = new Dictionary<string, JObject>();
            foreach (var file in new[] { "json_web_crypto_test.json", "json_web_signature_test.json" })
            {
                var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Wycheproof", file);
                vectorFiles.Add(file, JObject.Parse(File.ReadAllText(path)));
            }
            return vectorFiles;
        }

        private static IJwtAlgorithm CreateAlgorithm(string algorithmName, JObject key, out byte[] secret, out IDisposable disposableKey)
        {
            secret = null;
            disposableKey = null;

            switch (algorithmName)
            {
                case "HS256":
                    secret = UrlEncoder.Decode((string)key["k"]);
                    return new HMACSHA256Algorithm();
                case "HS384":
                    secret = UrlEncoder.Decode((string)key["k"]);
                    return new HMACSHA384Algorithm();
                case "HS512":
                    secret = UrlEncoder.Decode((string)key["k"]);
                    return new HMACSHA512Algorithm();
                case "RS256":
                case "RS384":
                case "RS512":
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters
                    {
                        Modulus = UrlEncoder.Decode((string)key["n"]),
                        Exponent = UrlEncoder.Decode((string)key["e"])
                    });
                    disposableKey = rsa;
                    if (algorithmName == "RS256") return new RS256Algorithm(rsa);
                    if (algorithmName == "RS384") return new RS384Algorithm(rsa);
                    return new RS512Algorithm(rsa);
                case "ES256":
                case "ES384":
                case "ES512":
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
                    if (algorithmName == "ES256") return new ES256Algorithm(ecdsa);
                    if (algorithmName == "ES384") return new ES384Algorithm(ecdsa);
                    return new ES512Algorithm(ecdsa);
#else
                    return null;
#endif
                default:
                    return null;
            }
        }

        private static bool IsCanonicalBase64Url(string value)
        {
            if (value.Length == 0)
                return true;

            foreach (var character in value)
            {
                if (!((character >= 'A' && character <= 'Z') ||
                      (character >= 'a' && character <= 'z') ||
                      (character >= '0' && character <= '9') ||
                      character == '-' || character == '_'))
                    return false;
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

#if NETCOREAPP3_1_OR_GREATER || NET6_0_OR_GREATER
        private static ECCurve GetCurve(string curve)
        {
            switch (curve)
            {
                case "P-256": return ECCurve.NamedCurves.nistP256;
                case "P-384": return ECCurve.NamedCurves.nistP384;
                case "P-521": return ECCurve.NamedCurves.nistP521;
                default: throw new NotSupportedException(curve);
            }
        }
#endif
    }
}
