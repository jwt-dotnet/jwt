// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

using System;
using Microsoft.AspNetCore.Authentication;

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

        public static AuthenticationBuilder AddJwt(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtAuthenticationOptions> configureOptions) =>
            builder.AddScheme<JwtAuthenticationOptions, JwtAuthenticationHandler>(authenticationScheme, configureOptions);
    }
}