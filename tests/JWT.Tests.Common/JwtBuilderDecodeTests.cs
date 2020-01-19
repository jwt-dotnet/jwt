using System;
using System.Collections.Generic;
using FluentAssertions;
using JWT.Builder;
using JWT.Serializers;
using JWT.Tests.Common.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtBuilderDecodeTests
    {
        [TestMethod]
        public void DecodeToken()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because the decoded TestData.Token contains values and they should have been fetched");
        }

        [TestMethod]
        public void DecodeToken_WithoutAlgorithm_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodingWithoutAlgorithm =
                () => builder.WithAlgorithm(null)
                             .Decode(TestData.Token);

            decodingWithoutAlgorithm.Should()
                                    .Throw<InvalidOperationException>("because a TestData.Token can't be decoded without a valid algorithm");
        }

        [TestMethod]
        public void DecodeToken_WithoutAlgorithmFactory_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodingWithoutAlgorithm =
                () => builder.WithAlgorithm(null)
                             .WithAlgorithmFactory(null)
                             .Decode(TestData.Token);

            decodingWithoutAlgorithm.Should()
                                    .Throw<InvalidOperationException>("because a TestData.Token can't be decoded without a valid algorithm or algorithm factory");
        }

        [TestMethod]
        public void DecodeToken_WithoutToken_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodingANullJwt =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .Decode(null);

            decodingANullJwt.Should()
                            .Throw<ArgumentException>("because null is not a valid value for a TestData.Token");
        }

        [TestMethod]
        public void DecodeToken_WithoutSerializer_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodeJwtWithNullSerializer =
                () => builder.WithSerializer(null)
                             .Decode(TestData.Token);

            decodeJwtWithNullSerializer.Should()
                                       .Throw<InvalidOperationException>("because a TestData.Token can't be decoded without a valid serializer");
        }

        [TestMethod]
        public void DecodeToken_WithSerializer()
        {
            var builder = new JwtBuilder();
            var serializer = new JsonNetSerializer();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithSerializer(serializer)
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because the TestData.Token should be correctly decoded and its data extracted");
        }

        [TestMethod]
        public void DecodeToken_WithoutUrlEncoder_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodeJwtWithNullEncoder =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithUrlEncoder(null)
                             .Decode(TestData.Token);

            decodeJwtWithNullEncoder.Should()
                                    .Throw<InvalidOperationException>("because a TestData.Token can't be decoded without a valid UrlEncoder");
        }

        [TestMethod]
        public void DecodeToken_WithUrlEncoder()
        {
            var builder = new JwtBuilder();
            var urlEncoder = new JwtBase64UrlEncoder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithUrlEncoder(urlEncoder)
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because the TestData.Token should have been correctly decoded with the valid base 64 encoder");
        }

        [TestMethod]
        public void DecodeToken_WithoutTimeProvider_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodingJwtWithNullDateTimeProvider =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithDateTimeProvider(null)
                             .Decode(TestData.Token);

            decodingJwtWithNullDateTimeProvider.Should()
                                               .Throw<InvalidOperationException>("because a TestData.Token can't be decoded without a valid DateTimeProvider");
        }

        [TestMethod]
        public void DecodeToken_WithDateTimeProvider()
        {
            var builder = new JwtBuilder();
            var dateTimeProvider = new UtcDateTimeProvider();


            var payload = builder.WithDateTimeProvider(dateTimeProvider)
                                 .WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because the decoding process must be successful with a valid DateTimeProvider");
        }

        [TestMethod]
        public void DecodeToken_WithoutValidator()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithValidator(null)
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because a JWT should not necessary have a validator to be decoded");
        }

        [TestMethod]
        public void DecodeToken_WithExplicitValidator()
        {
            var builder = new JwtBuilder();
            var validator = new JwtValidator(
                new JsonNetSerializer(),
                new UtcDateTimeProvider());

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithValidator(validator)
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because a JWT should be correctly decoded, even with a validator");
        }

        [TestMethod]
        public void DecodeToken_WithVerifySignature()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithSecret(TestData.Secret)
                                 .MustVerifySignature()
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because the signature must have been verified successfully and the JWT correctly decoded");
        }

        [TestMethod]
        public void DecodeToken_WithVerifySignature_MultipleSecrets()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithSecret(TestData.Secrets)
                                 .MustVerifySignature()
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because one of the provided signatures must have been verified successfully and the JWT correctly decoded");
        }

        [TestMethod]
        public void DecodeToken_WithoutVerifySignature()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .DoNotVerifySignature()
                                 .Decode(TestData.Token);

            payload.Should()
                   .NotBeEmpty("because the TestData.Token should have been decoded without errors if asked so");
        }

        [TestMethod]
        public void DecodeToken_ToDictionary()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithSecret(TestData.Secret)
                                 .MustVerifySignature()
                                 .Decode<Dictionary<string, string>>(TestData.Token);

            payload.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys")
                   .And.Contain("FirstName", "Jesus")
                   .And.Contain("Age", 33.ToString());
        }

        [TestMethod]
        public void DecodeToken_ToDictionary_MultipleSecrets()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithSecret(TestData.Secrets)
                                 .MustVerifySignature()
                                 .Decode<Dictionary<string, string>>(TestData.Token);

            payload.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys")
                   .And.Contain("FirstName", "Jesus")
                   .And.Contain("Age", 33.ToString());
        }

        [TestMethod]
        public void DecodeToken_ToObject_MultipleSecrets()
        {
            var builder = new JwtBuilder();

            var payload = builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                                 .WithSecret(TestData.Secrets)
                                 .MustVerifySignature()
                                 .Decode<Customer>(TestData.Token);

            payload.FirstName.Should().Be("Jesus");
            payload.Age.Should().Be(33);
        }


        [TestMethod]
        public void DecodeToken_ToDictionary_WithoutSerializer_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodeJwtWithNullSerializer =
                () => builder.WithAlgorithm(TestData.HMACSHA256Algorithm)
                             .WithSerializer(null)
                             .WithSecret(TestData.Secret)
                             .MustVerifySignature()
                             .Decode<Dictionary<string, string>>(TestData.Token);

            decodeJwtWithNullSerializer.Should()
                                       .Throw<InvalidOperationException>("because a TestData.Token can't be decoded without a valid serializer");
        }
    }
}