using System;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static JWT.Internal.EncodingHelper;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtValidatorTests
    {
        [DataTestMethod]
        [DataRow(null, null, null)]
        [DataRow("", null, null)]
        [DataRow("{}", null, null)]
        [DataRow("{}", TestData.Token, null)]
        [DataRow("{}", TestData.Token, "")]
        public void Validate_Should_Throw_Exception_When_Argument_Is_Null_Or_Empty(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            var jwtValidator = new JwtValidator(null, null);

            Action validateJwtWithNullOrEmptyArgument =
                () => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);

            validateJwtWithNullOrEmptyArgument.Should()
                                              .Throw<ArgumentException>("because the JWT argument must not be null or empty");
        }

        [TestMethod]
        public void Validate_Should_Throw_Exception_When_Crypto_Does_Not_Match_Signature()
        {
            const string token = TestData.Token;
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(token);
            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes("ABC"), bytesToSign);
            ++signatureData[0]; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);

            Action validateJwtWithBadSignature =
                () => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);

            validateJwtWithBadSignature.Should()
                                       .Throw<SignatureVerificationException>("because the signature does not match the crypto");
        }

        [TestMethod]
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

        [DataTestMethod]
        [DataRow(null, null, null)]
        [DataRow("", null, null)]
        [DataRow("{}", null, null)]
        [DataRow("{}", TestData.Token, null)]
        [DataRow("{}", TestData.Token, "")]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Argument_Is_Null_Or_Empty(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            var jwtValidator = new JwtValidator(null, null);

            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeFalse("because the token should not have been validated");

            ex.Should()
              .NotBeNull("because an exception should have been thrown during the process");
        }

        [TestMethod]
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
            ++signatureData[0]; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeFalse("because the token should not have been validated");

            ex.Should()
              .NotBeNull("because an exception should have been thrown during the process");
        }

        [TestMethod]
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

            isValid.Should()
                   .BeTrue("because the token should have been validated");

            ex.Should()
              .BeNull("because a valid token verified should not raise any exception");
        }
    }
}
