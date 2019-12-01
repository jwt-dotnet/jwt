// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

using System;
using Microsoft.Extensions.DependencyInjection;

namespace JWT
{
    /// <summary>
    /// Extension methods for setting up JWT authentication/authorization middleware in an <see cref="IServiceCollection" />.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds authentication/authorization using JWT to the specified <see cref="IServiceCollection" />.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <returns>
        /// The <see cref="IServiceCollection" />.
        /// </returns>
        public static IServiceCollection AddJwt(this IServiceCollection services)
        {
            if (services == null)
                throw new ArgumentNullException(nameof(services));

            return services;
        }

        /// <summary>
        /// Adds authentication/authorization using JWT to the specified <see cref="IServiceCollection" />.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <param name="configureOptions">An <see cref="Action{JwtOptions}"/> to configure the provided <see cref="JwtOptions"/>.</param>
        /// <returns>
        /// The <see cref="IServiceCollection" />.
        /// </returns>
        public static IServiceCollection AddJwt(this IServiceCollection services, Action<JwtOptions> configureOptions)
        {
            if (services == null)
                throw new ArgumentNullException(nameof(services));
            if (configureOptions == null)
                throw new ArgumentNullException(nameof(configureOptions));

            services.Configure(configureOptions);

            return services;
        }
    }
}