// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

using System;
using Microsoft.AspNetCore.Builder;

namespace JWT
{
    /// <summary>
    /// Extension methods for <see cref="IApplicationBuilder"/> to add the JWT authentication/authorization to the pipeline.
    /// </summary>
    public static class ApplicationBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="JwtAuthenticationMiddleware" /> to the specified <see cref="IApplicationBuilder" />, which enables authentication/authorization using JWT.
        /// </summary>
        /// <returns>
        /// The <see cref="IApplicationBuilder" />.
        /// </returns>
        public static IApplicationBuilder UseJwt(this IApplicationBuilder app)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            return app.UseMiddleware<JwtAuthenticationMiddleware>();
        }
    }
}