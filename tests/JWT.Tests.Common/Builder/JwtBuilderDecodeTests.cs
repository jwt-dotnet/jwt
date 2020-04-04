using System;
using System.Collections.Generic;
using FluentAssertions;
using JWT.Builder;
using JWT.Serializers;
using JWT.Tests.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Builder
{
    [TestClass]
    public class JwtBuilderDecodeTests
    {

        [TestMethod]
        public void DecodeHeader_Should_Return_Header()
        {
            var builder = new JwtBuilder();

            var header = builder.WithAlgorithm(TestData.RS256Algorithm)
                                .DecodeHeader(TestData.TokenByAsymmetricAlgorithm);

            header.Should()
                  .NotBeNullOrEmpty("because decoding header should be possible without validator or algorithm");
        }

        [TestMethod]
        public void DecodeHeader_To_JwtHeader_Should_Return_Header()
        {
            var builder = new JwtBuilder();

            var header = builder.DecodeHeader<JwtHeader>(TestData.TokenByAsymmetricAlgorithm);

            header.Should()
                  .NotBeNull("because decoding header should be possible without validator or algorithm");

            header.Type
                  .Should()
                  .Be("JWT");
            header.Algorithm
                  .Should()
                  .Be("RS256");
            header.KeyId
                  .Should()
                  .Be(TestData.ServerRsaPublicThumbprint1);
        }

        [TestMethod]
        public void DecodeHeader_To_Dictionary_Should_Return_Header()
        {
            var builder = new JwtBuilder();

            var header = builder.WithAlgorithm(TestData.RS256Algorithm)
                                .DecodeHeader<Dictionary<string, string>>(TestData.TokenByAsymmetricAlgorithm);

            header.Should()
                  .NotBeNull("because decoding header should be possible without validator or algorithm");

            header.Should()
                  .Contain("typ", "JWT")
                  .And.Contain("alg", "RS256")
                  .And.Contain("kid", TestData.ServerRsaPublicThumbprint1);
        }

        [TestMethod]
        public void Decode_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .Decode(TestData.Token);

            token.Should()
                 .NotBeNullOrEmpty("because the decoded token contains values and they should have been decoded");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_And_Without_Algorithm_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(null)
                             .MustVerifySignature()
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid algorithm");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_And_Without_AlgorithmFactory_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithmFactory(null)
                             .MustVerifySignature()
                             .Decode(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid algorithm or algorithm factory");
        }

        [TestMethod]
        public void Decode_Without_VerifySignature_And_Without_Algorithm_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(null)
                               .WithValidator(null)
                               .DoNotVerifySignature()
                               .Decode(TestData.Token);

            token.Should()
                 .NotBeNullOrEmpty("because the decoding process without validating signature must be successful without validator and algorithm");
        }

        [TestMethod]
        public void Decode_Without_VerifySignature_And_Without_AlgorithmFactory_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithmFactory(null)
                               .WithValidator(null)
                               .DoNotVerifySignature()
                               .Decode(TestData.Token);

            token.Should()
                 .NotBeNullOrEmpty("because the decoding process without validating signature must be successful without validator and algorithm factory");
        }

        [TestMethod]
        public void Decode_Without_Token_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodingANullJwt =
                () => builder.WithAlgorithm(TestData.RS256Algorithm)
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

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .WithSerializer(serializer)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeNullOrEmpty("because token should be correctly decoded and its data extracted");
        }

        [TestMethod]
        public void Decode_Without_UrlEncoder_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.RS256Algorithm)
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

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .WithUrlEncoder(urlEncoder)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeNullOrEmpty("because token should have been correctly decoded with the valid base64 encoder");
        }

        [TestMethod]
        public void Decode_Without_TimeProvider_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action action =
                () => builder.WithAlgorithm(TestData.RS256Algorithm)
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
                               .WithAlgorithm(TestData.RS256Algorithm)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeNullOrEmpty("because the decoding process must be successful with valid DateTimeProvider");
        }

        [TestMethod]
        public void Decode_Without_Validator_Should_Return_Token()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .WithValidator(null)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeNullOrEmpty("because a JWT should not necessary have validator to be decoded");
        }

        [TestMethod]
        public void Decode_With_ExplicitValidator_Should_Return_Token()
        {
            var builder = new JwtBuilder();
            var validator = new JwtValidator(
                new JsonNetSerializer(),
                new UtcDateTimeProvider());

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .WithValidator(validator)
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeNullOrEmpty("because a JWT should be correctly decoded, even with validator");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_Should_Return_Token_When_Algorithm_Is_Symmetric()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secret)
                               .MustVerifySignature()
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeNullOrEmpty("because the signature must have been verified successfully and the JWT correctly decoded");
        }

        [TestMethod]
        public void Decode_With_VerifySignature_Should_Return_Token_When_Algorithm_Is_Asymmetric()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .MustVerifySignature()
                               .Decode(TestData.TokenByAsymmetricAlgorithm);

            token.Should()
                 .NotBeNullOrEmpty("because the signature must have been verified successfully and the JWT correctly decoded");
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
                 .NotBeNullOrEmpty("because one of the provided signatures must have been verified successfully and the JWT correctly decoded");
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

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .DoNotVerifySignature()
                               .Decode(TestData.Token);

            token.Should()
                   .NotBeNullOrEmpty("because token should have been decoded without errors");
        }

        [TestMethod]
        public void Decode_To_Dictionary_Should_Return_Dictionary_When_Algorithm_Is_Symmetric()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secret)
                               .MustVerifySignature()
                               .Decode<Dictionary<string, object>>(TestData.Token);

            token.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys")
                   .And.Contain("FirstName", "Jesus")
                   .And.Contain("Age", 33);
        }

        [TestMethod]
        public void Decode_To_Dictionary_Should_Return_Dictionary_When_Algorithm_Is_Asymmetric()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.RS256Algorithm)
                               .MustVerifySignature()
                               .Decode<Dictionary<string, object>>(TestData.TokenByAsymmetricAlgorithm);

            token.Should()
                 .HaveCount(4, "because there are so many encoded claims that should be resulting in so many keys")
                 .And.Contain(nameof(Customer.FirstName), "Jesus")
                 .And.Contain(nameof(Customer.Age), 33)
                 .And.Contain("iss", "test")
                 .And.ContainKey("exp");
        }

        [TestMethod]
        public void Decode_ToDictionary_With_Multiple_Secrets_Should_Return_Dictionary()
        {
            var builder = new JwtBuilder();

            var token = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                               .WithSecret(TestData.Secrets)
                               .MustVerifySignature()
                               .Decode<Dictionary<string, object>>(TestData.Token);

            token.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys")
                   .And.Contain("FirstName", "Jesus")
                   .And.Contain("Age", 33);
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
                () => builder.WithAlgorithm(TestData.RS256Algorithm)
                             .WithSerializer(null)
                             .WithSecret(TestData.Secret)
                             .MustVerifySignature()
                             .Decode<Dictionary<string, string>>(TestData.Token);

            action.Should()
                  .Throw<InvalidOperationException>("because token can't be decoded without valid serializer");
        }
    }
}