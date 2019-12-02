﻿using System;
using Microsoft.AspNetCore.Authentication;

namespace JWT
{
    public static class AuthenticationAppBuilderExtensions
    {
        public const string SchemaName = "Jwt";

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder) =>
            builder.AddJwt(SchemaName);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme) =>
            builder.AddJwt(authenticationScheme, null);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, Action<JwtAuthenticationOptions> configureOptions) =>
            builder.AddJwt(SchemaName, configureOptions);

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtAuthenticationOptions> configureOptions) =>
            builder.AddScheme<JwtAuthenticationOptions, JwtAuthenticationHandler>(authenticationScheme, configureOptions);
    }
}