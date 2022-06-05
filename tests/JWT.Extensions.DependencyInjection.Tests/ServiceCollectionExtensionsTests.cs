using System;
using FluentAssertions;
using JWT.Algorithms;
using JWT.Tests.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Extensions.DependencyInjection.Tests
{
    [TestClass]
    public class ServiceCollectionExtensionsTests
    {
        [TestMethod]
        public void AddJwtEncoder_Without_AlgorithmFactory_Should_Throw_Exception()
        {
            var services = new ServiceCollection();
            services.AddJwtEncoder();

            var provider = services.BuildServiceProvider();
            Action action = () => provider.GetRequiredService<IJwtEncoder>();

            action.Should().Throw<InvalidOperationException>();
        }

        [TestMethod]
        public void AddJwtEncoder_And_Register_AlgorithmFactory_Should_Register_JwtEncoder()
        {
            var services = new ServiceCollection();
            services.AddJwtEncoder()
                    .AddSingleton<IAlgorithmFactory>(_ => new DelegateAlgorithmFactory(TestData.HMACSHA256Algorithm));

            var provider = services.BuildServiceProvider();
            var encoder = provider.GetRequiredService<IJwtEncoder>();
            encoder.Should().NotBeNull();

            var payload = TestData.DictionaryPayload;
            const string key = TestData.Secret;
            var jwt = encoder.Encode(payload, key);
            jwt.Should().NotBeNull();
        }

        [TestMethod]
        public void AddJwtEncoder_With_Algorithm_Generic_Type_Should_Register_JwtEncoder()
        {
            var services = new ServiceCollection();
            services.AddJwtEncoder<HMACSHA256Algorithm>();

            var provider = services.BuildServiceProvider();
            var encoder = provider.GetRequiredService<IJwtEncoder>();
            encoder.Should().NotBeNull();

            var payload = TestData.DictionaryPayload;
            const string key = TestData.Secret;
            var jwt = encoder.Encode(payload, key);
            jwt.Should().NotBeNull();
        }

        [TestMethod]
        public void AddJwtEncoder_With_Algorithm_Should_Register_JwtEncoder()
        {
            var services = new ServiceCollection();
            services.AddJwtEncoder(TestData.HMACSHA256Algorithm);

            var provider = services.BuildServiceProvider();
            var encoder = provider.GetRequiredService<IJwtEncoder>();
            encoder.Should().NotBeNull();

            var payload = TestData.DictionaryPayload;
            const string key = TestData.Secret;
            var jwt = encoder.Encode(payload, key);
            jwt.Should().NotBeNull();
        }

        [TestMethod]
        public void AddJwtEncoder_With_Algorithm_Func_Should_Register_JwtEncoder()
        {
            var services = new ServiceCollection();
            services.AddJwtEncoder(() => TestData.HMACSHA256Algorithm);

            var provider = services.BuildServiceProvider();
            var encoder = provider.GetRequiredService<IJwtEncoder>();
            encoder.Should().NotBeNull();

            var payload = TestData.DictionaryPayload;
            const string key = TestData.Secret;
            var jwt = encoder.Encode(payload, key);
            jwt.Should().NotBeNull();
        }

        [TestMethod]
        public void AddJwtDecoder_Without_AlgorithmFactory_Should_Register_JwtDecoder_That_Cannot_Validate()
        {
            var services = new ServiceCollection();
            services.AddJwtDecoder();

            var provider = services.BuildServiceProvider();
            var decoder = provider.GetRequiredService<IJwtDecoder>();

            Action action = () => decoder.Decode(TestData.Token, TestData.Secret, true);

            action.Should().Throw<InvalidOperationException>();
        }

        [TestMethod]
        public void AddJwtDecoder_And_Register_AlgorithmFactory_Should_Register_JwtDecoder()
        {
            var services = new ServiceCollection();
            services.AddJwtDecoder()
                    .AddSingleton<IAlgorithmFactory, HMACSHAAlgorithmFactory>();

            var provider = services.BuildServiceProvider();
            var decoder = provider.GetRequiredService<IJwtDecoder>();
            decoder.Should().NotBeNull();

            const string token = TestData.Token;
            var payload = decoder.Decode(token, TestData.Secret);
            payload.Should().NotBeNull();
        }

        [TestMethod]
        public void AddJwtDecoder_With_AlgorithmFactory_Should_Register_JwtDecoder()
        {
            var services = new ServiceCollection();
            services.AddJwtDecoder<HMACSHAAlgorithmFactory>();

            var provider = services.BuildServiceProvider();
            var decoder = provider.GetRequiredService<IJwtDecoder>();
            decoder.Should().NotBeNull();

            const string token = TestData.Token;
            var payload = decoder.Decode(token, TestData.Secret);
            payload.Should().NotBeNull();
        }
    }
}