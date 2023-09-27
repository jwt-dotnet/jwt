using System;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using JWT.Tests.Models;
using JWT.Tests.Stubs;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using static JWT.Internal.EncodingHelper;

namespace JWT.Tests
{
    [TestClass]
    public class JwtValidatorTests
    {
        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_Serializer_Is_Null()
        {
            var dateTimeProvider = new UtcDateTimeProvider();

            Action action = () => new JwtValidator(null, dateTimeProvider);

            action.Should()
                  .Throw<ArgumentNullException>("because the serializer must not be null");
        }

        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_DateTimeProvider_Is_Null()
        {
            var serializer = CreateSerializer();

            Action action = () => new JwtValidator(serializer, null);

            action.Should()
                  .Throw<ArgumentException>("because the DateTime provider must not be null");
        }

        [TestMethod]
        public void Ctor_Should_Throw_Exception_When_ValidationParameters_Are_Null()
        {
            var serializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();

            Action action = () => new JwtValidator(serializer, dateTimeProvider, null);

            action.Should()
                  .Throw<ArgumentException>("because the validation parameters must not be null");
        }


        [DataTestMethod]
        [DataRow(null, null, null)]
        [DataRow("", null, null)]
        [DataRow("{}", null, null)]
        [DataRow("{}", TestData.Token, null)]
        [DataRow("{}", TestData.Token, "")]
        public void Validate_Should_Throw_Exception_When_Argument_Is_Null_Or_Empty(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);

            Action action = () => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);

            action.Should()
                  .Throw<ArgumentException>("because the JWT argument must not be null or empty");
        }

        [TestMethod]
        public void Validate_Should_Throw_Exception_When_Signature_Is_Invalid()
        {
            const string token = TestData.Token;
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(token);
            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            ++signatureData[0]; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);

            Action action = () => jwtValidator.Validate(payloadJson, decodedCrypto, decodedSignature);

            action.Should()
                  .Throw<SignatureVerificationException>("because signature is invalid");
        }

        [TestMethod]
        public void Validate_Should_Not_Throw_Exception_When_Crypto_Matches_Signature()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(TestData.Token);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);
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
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();
            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);

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
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(TestData.Token);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            ++signatureData[0]; // malformed signature
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);
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
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new UtcDateTimeProvider();

            var jwt = new JwtParts(TestData.Token);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeTrue("because token should be valid");

            ex.Should()
              .BeNull("because valid token should not throw exception: {0}", ex?.Message);
        }

        [TestMethod]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Token_Is_Expired()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp));

            var jwt = new JwtParts(TestData.TokenWithExp);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);
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
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp - 1));

            var jwt = new JwtParts(TestData.TokenWithExp);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);
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
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp));
            var valParams = ValidationParameters.Default.With(p => p.TimeMargin = 1);

            var jwt = new JwtParts(TestData.TokenWithExp);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider, valParams);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            ex.Should()
              .BeNull("because valid token should not throw exception: {0}", ex?.Message);

            isValid.Should()
                   .BeTrue("because token should be valid");
        }

        [TestMethod]
        public void TryValidate_Should_Return_False_And_Exception_Not_Null_When_Token_Is_Not_Yet_Usable()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp - 1));

            var jwt = new JwtParts(TestData.TokenWithNbf);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeFalse("because token should be invalid");

            ex.Should()
              .NotBeNull("because invalid token should thrown exception")
              .And.BeOfType(typeof(TokenNotYetValidException), "because not yet usable token should thrown TokenNotYetValidException");
        }

        [TestMethod]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Token_Is_Usable()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp));

            var jwt = new JwtParts(TestData.TokenWithNbf);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            isValid.Should()
                   .BeTrue("because token should be valid");

            ex.Should()
              .BeNull("because valid token should not throw exception");
        }

        [TestMethod]
        public void TryValidate_Should_Return_True_And_Exception_Null_When_Token_Is_Not_Yet_Valid_But_Validator_Has_Time_Margin()
        {
            var urlEncoder = new JwtBase64UrlEncoder();
            var jsonSerializer = CreateSerializer();
            var dateTimeProvider = new StaticDateTimeProvider(DateTimeOffset.FromUnixTimeSeconds(TestData.TokenTimestamp - 1));
            var valParams = ValidationParameters.Default.With(p => p.TimeMargin = 1);

            var jwt = new JwtParts(TestData.TokenWithNbf);

            var payloadJson = GetString(urlEncoder.Decode(jwt.Payload));

            var crypto = urlEncoder.Decode(jwt.Signature);
            var decodedCrypto = Convert.ToBase64String(crypto);

            var alg = new HMACSHA256Algorithm();
            var bytesToSign = GetBytes(String.Concat(jwt.Header, ".", jwt.Payload));
            var signatureData = alg.Sign(GetBytes(TestData.Secret), bytesToSign);
            var decodedSignature = Convert.ToBase64String(signatureData);

            var jwtValidator = new JwtValidator(jsonSerializer, dateTimeProvider, valParams);
            var isValid = jwtValidator.TryValidate(payloadJson, decodedCrypto, decodedSignature, out var ex);

            ex.Should()
              .BeNull("because valid token should not throw exception: {0}", ex?.Message);

            isValid.Should()
                   .BeTrue("because token should be valid");

        }

        [TestMethod]
        public void ValidationParameters_Ctor_Should_Set_All_Validation_To_True()
        {
            var valParams = new ValidationParameters();

            valParams.ValidateSignature.Should()
                     .BeTrue("because ValidationParameters constructor should set ValidateSignature to true");
            valParams.ValidateExpirationTime.Should()
                     .BeTrue("because ValidationParameters constructor should set ValidateExpirationTime to true");
            valParams.ValidateIssuedTime.Should()
                     .BeTrue("because ValidationParameters constructor should set ValidateIssuedTime to true");
            valParams.TimeMargin.Should()
                     .Be(0, "because ValidationParameters constructor should set TimeMargin to 0");
        }

        [TestMethod]
        public void ValidationParameters_Ctor_Should_Allow_Default_Values_To_Be_Overriden()
        {
            var valParams = new ValidationParameters
            {
                ValidateSignature = false,
                ValidateExpirationTime = false,
                ValidateIssuedTime = false,
                TimeMargin = 300
            };

            valParams.ValidateSignature.Should()
                     .BeFalse("because ValidationParameters constructor should allow ValidateSignature to be overridden");
            valParams.ValidateExpirationTime.Should()
                     .BeFalse("because ValidationParameters constructor should allow ValidateExpirationTime to be overridden");
            valParams.ValidateIssuedTime.Should()
                     .BeFalse("because ValidationParameters constructor should allow ValidateIssuedTime to be overridden");
            valParams.TimeMargin.Should()
                     .Be(300, "because ValidationParameters constructor should allow TimeMargin to be overridden");
        }

        [TestMethod]
        public void ValidationParameters_Default_Should_Set_All_Validation_To_True()
        {
            var valParams = ValidationParameters.Default;

            valParams.ValidateSignature.Should()
                     .BeTrue("because ValidationParameters.Default should set ValidateSignature to true");
            valParams.ValidateExpirationTime.Should()
                     .BeTrue("because ValidationParameters.Default should set ValidateExpirationTime to true");
            valParams.ValidateIssuedTime.Should()
                     .BeTrue("because ValidationParameters.Default should set ValidateIssuedTime to true");
            valParams.TimeMargin.Should()
                     .Be(0, "because ValidationParameters.Default should set TimeMargin to 0");
        }

        [TestMethod]
        public void ValidationParameters_None_Should_Set_All_Validation_To_False()
        {
            var valParams = ValidationParameters.None;

            valParams.ValidateSignature.Should()
                     .BeFalse("because ValidationParameters.None should set ValidateSignature to false");
            valParams.ValidateExpirationTime.Should()
                     .BeFalse("because ValidationParameters.DefaNoneult should set ValidateExpirationTime to false");
            valParams.ValidateIssuedTime.Should()
                     .BeFalse("because ValidationParameters.None should set ValidateIssuedTime to false");
            valParams.TimeMargin.Should()
                     .Be(0, "because ValidationParameters.Default should set TimeMargin to 0");
        }

        private static IJsonSerializer CreateSerializer() =>
            new DefaultJsonSerializerFactory().Create();
    }
}
