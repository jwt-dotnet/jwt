using System;
using System.Collections.Generic;
using FluentAssertions;
using JWT.Builder;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common.Builder
{
    [TestClass]
    public class JwtBuilderDecodeTests
    {
        [TestMethod]
        public void Decode_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because the decoded TestData.Token contains values and they should have been fetched");
        }

        [TestMethod]
        public void Decode_Without_Algorithm_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(null)
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid algorithm");
        }

        [TestMethod]
        public void Decode_Without_AlgorithmFactory_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(null)
                             .WithAlgorithmFactory(null)
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid algorithm or algorithm factory");
        }

        [TestMethod]
        public void Decode_Without_Token_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodingANullJwt =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .Decode(null);

            decodingANullJwt.Should()
                            .Throw<ArgumentException>("because null is not valid value for token");
        }

        [TestMethod]
        public void Decode_Without_Serializer_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithSerializer(null)
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid serializer");
        }

        [TestMethod]
        public void Decode_With_Serializer_Should_Return_Token()
        {
            var builder = new JwtBuilder();
            var serializer = new JsonNetSerializer();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSerializer(serializer)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because token should be correctly decoded and its data extracted");
        }

        [TestMethod]
        public void Decode_Without_UrlEncoder_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithUrlEncoder(null)
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid UrlEncoder");
        }

        [TestMethod]
        public void Decode_With_UrlEncoder_Should_Return_Token()
        {
            var builder = new JwtBuilder();
            var urlEncoder = new JwtBase64UrlEncoder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithUrlEncoder(urlEncoder)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because token should have been correctly decoded with the valid base 64 encoder");
        }

        [TestMethod]
        public void Decode_Without_TimeProvider_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithDateTimeProvider(null)
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid DateTimeProvider");
        }

        [TestMethod]
        public void Decode_With_DateTimeProvider_Should_Return_Token()
        {
            var builder = new JwtBuilder();
            var dateTimeProvider = new UtcDateTimeProvider();


            var token = builder.WithDateTimeProvider(dateTimeProvider)
                               .WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because the decoding process must be successful with valid DateTimeProvider");
        }

        [TestMethod]
        public void Decode_Without_Validator_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithValidator(null)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because a JWT should not necessary have validator to be decoded");
        }

        [TestMethod]
        public void Decode_With_ExplicitValidator_Should_Return_Token()
        {
            var builder = new JwtBuilder();
            var validator = new JwtValidator(
                new JsonNetSerializer(),
                new UtcDateTimeProvider());

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithValidator(validator)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because a JWT should be correctly decoded, even with validator");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secret)
                               .MustVerifySignature()
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because the signature must have been verified successfully and the JWT correctly decoded");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_With_Multiple_Secrets_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secrets)
                               .MustVerifySignature()
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because one of the provided signatures must have been verified successfully and the JWT correctly decoded");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_With_Multiple_String_Secrets_Empty_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithSecret(new string[0])
                             .MustVerifySignature()
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<ArgumentOutOfRangeException>("because secret can't be empty");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_With_Multiple_Byte_Secrets_Empty_All_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithSecret(new byte[0])
                             .MustVerifySignature()
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<ArgumentOutOfRangeException>("because secrets can't be empty");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_With_Byte_Multiple_Secrets_Empty_One_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithSecret(new byte[0], new byte[1])
                             .MustVerifySignature()
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<ArgumentOutOfRangeException>("because secrets can't be empty");
        }

        [TestMethod]
        public void Decode_Without_VerifySignature_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .DoNotVerifySignature()
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeEmpty("because token should have been decoded without errors");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_Without_PrivateKey_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.RS256Algorithm)
                             .MustVerifySignature()
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because validating signature requires private key");
        }

        [TestMethod]
        public void Decode_To_Dictionary_Should_Return_Dictionary()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secret)
                               .MustVerifySignature()
                               .Decode<Dictionary<string, string>>(TestData.Token);

            token.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys")
                   .And.Contain("FirstName", "Jesus")
                   .And.Contain("Age", 33.ToString());
        }

        [TestMethod]
        public void Decode_ToDictionary_With_Multiple_Secrets_Should_Return_Dictionary()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secrets)
                               .MustVerifySignature()
                               .Decode<Dictionary<string, string>>(TestData.Token);

            token.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys")
                   .And.Contain("FirstName", "Jesus")
                   .And.Contain("Age", 33.ToString());
        }

        [TestMethod]
        public void Decode_ToObject_With_Multiple_Secrets_Should_Return_Object()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secrets)
                               .MustVerifySignature()
                               .Decode<Customer>(TestData.Token);

            token.FirstName.Should().Be("Jesus");
            token.Age.Should().Be(33);
        }

        [TestMethod]
        public void Decode_ToDictionary_Without_Serializer_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithSerializer(null)
                             .WithSecret(TestData.Secret)
                             .MustVerifySignature()
                             .Decode<Dictionary<string, string>>(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid serializer");
        }
    }
}