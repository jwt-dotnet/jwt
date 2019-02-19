using System;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Xunit;

using static JWT.Internal.EncodingHelper;

namespace JWT.Tests.Common
{
    public class JwtValidatorTest
    {
        [Theory]
        [InlineData(null, null, null)]
        [InlineData("", null, null)]
        [InlineData("{}", null, null)]
        [InlineData("{}", TestData.Token, null)]
        [InlineData("{}", TestData.Token, "")]
        public void Validate_Should_Throw_Exception_When_Argument_Is_Null_Or_Empty(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            var jwtValidator = new JwtValidator(null, null);
            Assert.Throws<ArgumentException>(() => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature));
        }

        [Fact]
        public void Validate_Should_Throw_Exception_When_Crypto_Does_Not_Match_Signature()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(TestData.Token);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes("ABC"), bytesToSign);
            signatureData[0]++; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            Assert.Throws<SignatureVerificationException>(() => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature));
        }

        [Fact]
        public void Validate_Should_Not_Throw_Exception_When_Crypto_Matches_Signature()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(TestData.Token);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes("ABC"), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);
        }

        [Theory]
        [InlineData(null, null, null)]
        [InlineData("", null, null)]
        [InlineData("{}", null, null)]
        [InlineData("{}", TestData.Token, null)]
        [InlineData("{}", TestData.Token, "")]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Argument_Is_Null_Or_Empty(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            var jwtValidator = new JwtValidator(null, null);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);
            Assert.False(isValid);
            Assert.NotNull(ex);
        }

        [Fact]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Crypto_Matches_Signature()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(TestData.Token);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes("ABC"), bytesToSign);
            signatureData[0]++; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            Assert.False(isValid);
            Assert.NotNull(ex);
        }

        [Fact]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Crypto_Matches_Signature()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(TestData.Token);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes("ABC"), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            Assert.True(isValid);
            Assert.Null(ex);
        }
    }
}