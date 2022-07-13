using System;
using JWT.Algorithms;
using JWT.Extensions.AspNetCore.Factories;
using JWT.Extensions.AspNetCore.Internal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JWT.Extensions.AspNetCore
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
            builder.Services.AddJwtDecoder();
            builder.Services.TryAddSingleton<IDateTimeProvider, SystemClockDatetimeProvider>();

            builder.Services.TryAddSingleton<IIdentityFactory, ClaimsIdentityFactory>();
            builder.Services.TryAddSingleton<ITicketFactory, DefaultTicketFactory>();

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
            builder.Services.AddJwtDecoder<TFactory>();

            return builder.AddJwt(authenticationScheme, configureOptions);
        }
    }
}
