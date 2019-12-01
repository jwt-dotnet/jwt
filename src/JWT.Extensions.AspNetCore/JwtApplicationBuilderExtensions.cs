// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See LICENSE.MIT.txt file in the repository root for license information.

using System;
using Microsoft.AspNetCore.Builder;

namespace JWT
{
    /// <summary>
    /// Extension methods to ???
    /// </summary>
    public static class JwtApplicationBuilderExtensions
    {
        /// <summary>
        /// Finalizes the configuration of Simple Injector on top of <see cref="IServiceCollection"/>. Will
        /// ensure framework components can be injected into Simple Injector-resolved components, unless
        /// <see cref="SimpleInjectorUseOptions.AutoCrossWireFrameworkComponents"/> is set to <c>false</c>.
        /// </summary>
        /// <param name="app">The application's <see cref="IApplicationBuilder"/>.</param>
        /// <param name="container">The application's <see cref="Container"/> instance.</param>
        /// <returns>The supplied <paramref name="app"/>.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="app"/> or
        /// <paramref name="container"/> are null references.</exception>
        public static IApplicationBuilder UseSimpleInjector(this IApplicationBuilder app, Action<JwtOptions> setupAction)
        {
            return app;
        }
    }
}