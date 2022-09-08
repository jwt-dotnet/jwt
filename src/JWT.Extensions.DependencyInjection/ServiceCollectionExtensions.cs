using System;
using JWT.Algorithms;
using JWT.Internal;
using JWT.Serializers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JWT
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddJwtEncoder(this IServiceCollection services)
        {
            services.TryAddSingleton<IJwtEncoder, JwtEncoder>();
            services.TryAddSingleton<IJsonSerializerFactory, DefaultJsonSerializerFactory>();
            services.TryAddSingleton<IJsonSerializer>(p => p.GetRequiredService<IJsonSerializerFactory>().Create());
            services.TryAddSingleton<IBase64UrlEncoder, JwtBase64UrlEncoder>();

            return services;
        }

        public static IServiceCollection AddJwtEncoder<TAlgo>(this IServiceCollection services)
            where TAlgo : IJwtAlgorithm, new() =>
            services.AddJwtEncoder(new GenericAlgorithmFactory<TAlgo>());

        public static IServiceCollection AddJwtEncoder(this IServiceCollection services, Func<IJwtAlgorithm> algFactory) =>
            services.AddJwtEncoder(new DelegateAlgorithmFactory(algFactory));

        public static IServiceCollection AddJwtEncoder(this IServiceCollection services, IJwtAlgorithm algorithm) =>
            services.AddJwtEncoder(() => algorithm);

        private static IServiceCollection AddJwtEncoder<TFactory>(this IServiceCollection services, TFactory algFactory)
            where TFactory : class, IAlgorithmFactory
        {
            services.TryAddSingleton<IAlgorithmFactory>(_ => algFactory);

            return services.AddJwtEncoder();
        }

        public static IServiceCollection AddJwtDecoder(this IServiceCollection services)
        {
            services.TryAddSingleton<IJwtDecoder, JwtDecoder>();
            services.TryAddSingleton<IJsonSerializerFactory, DefaultJsonSerializerFactory>();
            services.TryAddSingleton<IJsonSerializer>(p => p.GetRequiredService<IJsonSerializerFactory>().Create());
            services.TryAddSingleton<IJwtValidator, JwtValidator>();
            services.TryAddSingleton<IBase64UrlEncoder, JwtBase64UrlEncoder>();
            services.TryAddSingleton<IDateTimeProvider, UtcDatetimeProvider>();

            return services;
        }

        public static IServiceCollection AddJwtDecoder<TFactory>(this IServiceCollection services)
            where TFactory : class, IAlgorithmFactory
        {
            services.TryAddSingleton<IAlgorithmFactory, TFactory>();

            return services.AddJwtDecoder();
        }
    }
}
