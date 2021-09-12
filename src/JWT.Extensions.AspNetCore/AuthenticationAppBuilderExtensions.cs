using System;
using JWT.Algorithms;
using JWT.Internal;
using JWT.Serializers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JWT
{
    public static class AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder) =>
            builder.AddJwt(JwtAuthenticationDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme) =>
            builder.AddJwt(authenticationScheme, null);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, Action<JwtAuthenticationOptions> configureOptions) =>
            builder.AddJwt(JwtAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtAuthenticationOptions> configureOptions)
        {
            builder.Services.TryAddSingleton<IJwtDecoder, JwtDecoder>();
            builder.Services.TryAddSingleton<IJsonSerializer, JsonNetSerializer>();
            builder.Services.TryAddSingleton<IJwtValidator, JwtValidator>();
            builder.Services.TryAddSingleton<IBase64UrlEncoder, JwtBase64UrlEncoder>();

            builder.Services.TryAddSingleton<IDateTimeProvider, SystemClockDatetimeProvider>();

            return builder.AddScheme<JwtAuthenticationOptions, JwtAuthenticationHandler>(authenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddJwt<TFactory>(this AuthenticationBuilder builder)
            where TFactory : class, IAlgorithmFactory =>
            builder.AddJwt<TFactory>(JwtAuthenticationDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddJwt<TFactory>(this AuthenticationBuilder builder, string authenticationScheme)
            where TFactory : class, IAlgorithmFactory =>
            builder.AddJwt<TFactory>(authenticationScheme, null);

        public static AuthenticationBuilder AddJwt<TFactory>(this AuthenticationBuilder builder, Action<JwtAuthenticationOptions> configureOptions)
            where TFactory : class, IAlgorithmFactory =>
            builder.AddJwt<TFactory>(JwtAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddJwt<TFactory>(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtAuthenticationOptions> configureOptions)
            where TFactory : class, IAlgorithmFactory
        {
            builder.Services.TryAddSingleton<IAlgorithmFactory, TFactory>();

            return builder.AddJwt(authenticationScheme, configureOptions);
        }
    }
}