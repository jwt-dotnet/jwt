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
            services.TryAddSingleton<IJsonSerializer, JsonNetSerializer>();
            services.TryAddSingleton<IBase64UrlEncoder, JwtBase64UrlEncoder>();

            return services;
        }

        public static IServiceCollection AddJwtEncoder<TFactory>(this IServiceCollection services)
            where TFactory : class, IAlgorithmFactory
        {
            services.TryAddSingleton<IAlgorithmFactory, TFactory>();

            return services.AddJwtEncoder();
        }

        public static IServiceCollection AddJwtDecoder(this IServiceCollection services)
        {
            services.TryAddSingleton<IJwtDecoder, JwtDecoder>();
            services.TryAddSingleton<IJsonSerializer, JsonNetSerializer>();
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