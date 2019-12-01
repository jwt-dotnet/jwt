using System;
using System.Collections.Generic;
using FluentAssertions;
using JWT.Builder;
using JWT.Serializers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests.Common
{
    [TestClass]
    public class JwtBuilderDecodeTests
    {
        private const string _sampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
        private const string _sampleSecret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
        private readonly string[] _sampleSecrets = { "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk", "QWORIJkmQWEDIHbjhOIHAUSDFOYnUGWEYT" };

        [TestMethod]
        public void DecodeToken()
        {
            var payload = new JwtBuilder()
                .Decode(_sampleToken);

            payload.Should()
                   .NotBeEmpty("because the decoded token contains values and they should have been fetched");
        }

        [TestMethod]
        public void DecodeToken_WithoutToken_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();

            Action decodingANullJwt =
                () => builder.Decode(null);

            decodingANullJwt.Should()
                            .Throw<ArgumentException>("because null is not a valid value for a token");
        }

        [TestMethod]
        public void DecodeToken_WithoutSerializer_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            var serializer = (IJsonSerializer)null;
            const string token = _sampleToken;

            Action decodeJwtWithNullSerializer =
                () => builder.WithSerializer(serializer)
                             .Decode(token);

            decodeJwtWithNullSerializer.Should()
                                       .Throw<InvalidOperationException>("because a token can't be decoded without a valid serializer");
        }

        [TestMethod]
        public void DecodeToken_WithSerializer()
        {
            var builder = new JwtBuilder();
            var serializer = new JsonNetSerializer();
            const string token = _sampleToken;

            var payload = builder
                .WithSerializer(serializer)
                .Decode(token);

            payload.Should()
                   .NotBeEmpty("because the token should be correctly decoded and its data extracted");
        }

        [TestMethod]
        public void DecodeToken_WithoutUrlEncoder_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            var urlEncoder = (IBase64UrlEncoder)null;
            const string token = _sampleToken;

            Action decodeJwtWithNullEncoder =
               () => builder.WithUrlEncoder(urlEncoder)
                            .Decode(token);

            decodeJwtWithNullEncoder.Should()
                                    .Throw<InvalidOperationException>("because a token can't be decoded without a valid UrlEncoder");
        }

        [TestMethod]
        public void DecodeToken_WithUrlEncoder()
        {
            var builder = new JwtBuilder();
            var urlEncoder = new JwtBase64UrlEncoder();
            const string token = _sampleToken;

            var payload = builder
                          .WithUrlEncoder(urlEncoder)
                          .Decode(token);

            payload.Should()
                   .NotBeEmpty("because the token should have been correctly decoded with the valid base 64 encoder");
        }

        [TestMethod]
        public void DecodeToken_WithoutTimeProvider_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            var dateTimeProvider = (IDateTimeProvider)null;
            const string token = _sampleToken;

            Action decodingJwtWithNullDateTimeProvider =
                () => builder
                        .WithDateTimeProvider(dateTimeProvider)
                        .Decode(token);

            decodingJwtWithNullDateTimeProvider.Should()
                                               .Throw<InvalidOperationException>("because a token can't be decoded without a valid DateTimeProvider");
        }

        [TestMethod]
        public void DecodeToken_WithDateTimeProvider()
        {
            var builder = new JwtBuilder();
            var dateTimeProvider = new UtcDateTimeProvider();
            const string token = _sampleToken;


            var payload = builder
                          .WithDateTimeProvider(dateTimeProvider)
                          .Decode(token);

            payload.Should()
                   .NotBeEmpty("because the decoding process must be successful with a valid DateTimeProvider");
        }

        [TestMethod]
        public void DecodeToken_WithoutValidator()
        {
            var builder = new JwtBuilder();
            const string token = _sampleToken;
            var validator = (IJwtValidator)null;

            var payload = builder
                          .WithValidator(validator)
                          .Decode(token);

            payload.Should()
                   .NotBeEmpty("because a JWT should not necessary have a validator to be decoded");
        }

        [TestMethod]
        public void DecodeToken_WithExplicitValidator()
        {
            var builder = new JwtBuilder();
            const string token = _sampleToken;
            var validator = new JwtValidator(
                new JsonNetSerializer(),
                new UtcDateTimeProvider());

            var payload = builder
                          .WithValidator(validator)
                          .Decode(token);

            payload.Should()
                   .NotBeEmpty("because a JWT should be correctly decoded, even with a validator");
        }

        [TestMethod]
        public void DecodeToken_WithVerifySignature()
        {
            var builder = new JwtBuilder();
            const string secret = _sampleSecret;
            const string token = _sampleToken;

            var payload = builder
                          .WithSecret(secret)
                          .MustVerifySignature()
                          .Decode(token);

            payload.Should()
                   .NotBeEmpty("because the signature must have been verified successfully and the JWT correctly decoded");
        }

        [TestMethod]
        public void DecodeToken_WithVerifySignature_MultipleSecrets()
        {
            var builder = new JwtBuilder();
            var secrets = _sampleSecrets;
            const string token = _sampleToken;

            var payload = builder
                .WithSecret(secrets)
                .MustVerifySignature()
                .Decode(token);

            payload.Should()
                   .NotBeEmpty("because one of the provided signatures must have been verified successfully and the JWT correctly decoded");
        }

        [TestMethod]
        public void DecodeToken_WithoutVerifySignature()
        {
            var builder = new JwtBuilder();
            const string token = _sampleToken;

            var payload = builder
                .DoNotVerifySignature()
                .Decode(token);

            payload.Should()
                   .NotBeEmpty("because the token should have been decoded without errors if asked so");
        }

        [TestMethod]
        public void DecodeToken_ToDictionary()
        {
            var builder = new JwtBuilder();
            const string secret = _sampleSecret;
            const string token = _sampleToken;

            var payload = builder
                          .WithSecret(secret)
                          .MustVerifySignature()
                          .Decode<Dictionary<string, string>>(token);

            payload.Should()
                   .BeOfType<Dictionary<string, string>>("because the result should be of the requested type");

            payload.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys");

            payload["claim1"].Should()
                             .Be(0.ToString(), "because the key of the first claim should give its original value");
        }

        [TestMethod]
        public void DecodeToken_ToDictionary_MultipleSecrets()
        {
            var builder = new JwtBuilder();
            var secrets = _sampleSecrets;
            const string token = _sampleToken;

            var payload = builder
                .WithSecret(secrets)
                .MustVerifySignature()
                .Decode<Dictionary<string, string>>(token);

            payload.Should()
                   .BeOfType<Dictionary<string, string>>("because the result should be of the requested type");

            payload.Should()
                   .HaveCount(2, "because there is two encoded claims that should be resulting in two keys");

            payload["claim1"].Should()
                             .Be(0.ToString(), "because the key of the first claim should give its original value");
        }

        [TestMethod]
        public void DecodeToken_ToDictionary_WithoutSerializer_Should_Throw_Exception()
        {
            var builder = new JwtBuilder();
            const string secret = _sampleSecret;
            var serializer = (IJsonSerializer)null;
            const string token = _sampleToken;

            Action decodeJwtWithNullSerializer =
                () => builder
                        .WithSerializer(serializer)
                        .WithSecret(secret)
                        .MustVerifySignature()
                        .Decode<Dictionary<string, string>>(token);

            decodeJwtWithNullSerializer.Should()
                                       .Throw<InvalidOperationException>("because a token can't be decoded without a valid serializer");
        }
    }
}
