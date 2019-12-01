// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See LICENSE.md file in the repository root for license information.

using System;
using Microsoft.AspNetCore.Builder;

namespace JWT
{
    /// <summary>
    /// Extension methods for <see cref="IApplicationBuilder"/> to add the JWT authentication/authorization middleware to the pipeline.
    /// </summary>
    public static class ApplicationBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="JwtMiddleware" /> to the specified <see cref="IApplicationBuilder" />, which enables authentication/authorization middleware using JWT.
        /// </summary>
        /// <returns>
        /// The <see cref="IApplicationBuilder" />.
        /// </returns>
        public static IApplicationBuilder UseJwt(this IApplicationBuilder app)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            return app.UseMiddleware<JwtMiddleware>();
        }
    }
}