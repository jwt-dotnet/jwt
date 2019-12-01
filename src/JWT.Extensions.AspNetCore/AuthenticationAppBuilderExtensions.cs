// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

using System;
using Microsoft.AspNetCore.Authentication;

namespace JWT
{
    public static class AuthenticationAppBuilderExtensions
    {
        public const string SchemaName = "Jwt";

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder)
        {
            return builder.AddJwt(SchemaName);
        }

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder,
            string authenticationScheme)
        {
            return builder.AddJwt(authenticationScheme, (Action<JwtAuthenticationOptions>)null);
        }

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, Action<JwtAuthenticationOptions> configureOptions)
        {
            return builder.AddJwt(SchemaName, configureOptions);
        }

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtAuthenticationOptions> configureOptions)
        {
            return builder.AddScheme<JwtAuthenticationOptions, JwtAuthenticationHandler>(authenticationScheme, configureOptions);
        }
    }
}