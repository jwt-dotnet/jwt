using System;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using JWT.Tests.Stubs;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using static JWT.Internal.EncodingHelper;

namespace JWT.Tests
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

            Action action =
                () => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);

            action.Should()
                  .Throw<ArgumentException>("because the JWT argument must not be null or empty");
        }

        [TestMethod]
        public void Validate_Should_Throw_Exception_When_Signature_Is_Invalid()
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
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            ++signatureData[0]; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);

            Action action =
                () => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);

            action.Should()
                  .Throw<SignatureVerificationException>("because signature is invalid");
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
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
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
                   .BeFalse("because token should be invalid");

            ex.Should()
              .NotBeNull("because invalid token should thrown exception");
        }

        [TestMethod]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Signature_Is_Not_Valid()
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
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            ++signatureData[0]; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeFalse("because token should be invalid");

            ex.Should()
              .NotBeNull("because invalid token should thrown exception");
        }

        [TestMethod]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Crypto_Signature_Is_Valid()
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
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeTrue("because token should be valid");

            ex.Should()
              .BeNull("because valid token should not throw exception");
        }

        [TestMethod]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Token_Is_Expired()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp));

            var jwt = new JwtParts(TestData.TokenWithExp);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeFalse("because token should be invalid");

            ex.Should()
              .NotBeNull("because invalid token should thrown exception");

            ex.Should()
                .BeOfType(typeof(TokenExpiredException), "because expired token should thrown TokenExpiredException");
        }

        [TestMethod]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Token_Is_Not_Expired()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp - 1));

            var jwt = new JwtParts(TestData.TokenWithExp);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeTrue("because token should be valid");

            ex.Should()
              .BeNull("because valid token should not throw exception");
        }

        [TestMethod]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Token_Is_Expired_But_Validator_Has_Time_Margin()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp));

            var jwt = new JwtParts(TestData.TokenWithExp);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider, timeMargin: 1);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeTrue("because token should be valid");

            ex.Should()
              .BeNull("because valid token should not throw exception");
        }

        [TestMethod]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Token_Is_Not_Yet_Usable()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp - 1));

            var jwt = new JwtParts(TestData.TokenWithNbf);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeFalse("because token should be invalid");

            ex.Should()
              .NotBeNull("because invalid token should thrown exception");

            ex.Should()
                .BeOfType(typeof(SignatureVerificationException), "because not yet usable token should thrown SignatureVerificationException");
        }

        [TestMethod]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Token_Is_Usable()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp));

            var jwt = new JwtParts(TestData.TokenWithNbf);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeTrue("because token should be valid");

            ex.Should()
              .BeNull("because valid token should not throw exception");
        }

        [TestMethod]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Token_Is_Not_Yet_Usable_But_Validator_Has_Time_Margin()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonNetSerializer = new JsonNetSerializer();
            var utcDateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp - 1));

            var jwt = new JwtParts(TestData.TokenWithNbf);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonNetSerializer, utcDateTimeProvider, timeMargin: 1);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeTrue("because token should be valid");

            ex.Should()
              .BeNull("because valid token should not throw exception");
        }
    }
}
