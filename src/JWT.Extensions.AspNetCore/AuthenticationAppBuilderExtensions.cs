using System;
using JWT.Internal;
using JWT.Serializers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JWT
{
    public static class AuthenticationAppBuilderExtensions
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
    }
}