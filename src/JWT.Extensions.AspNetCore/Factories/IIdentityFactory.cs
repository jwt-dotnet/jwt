using System;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;

namespace JWT.Extensions.AspNetCore.Factories
{
    public interface IIdentityFactory
    {
        /// <summary>
        /// Creates <see cref="IIdentity" /> from the payload of the specified type.
        /// </summary>
        IIdentity CreateIdentity(Type type, object payload);

        /// <summary>
        /// Creates <see cref="IIdentity" /> from the payload of the specified type for the specified <see cref="AuthenticationScheme" />.
        /// </summary>
        /// <remarks>
        /// The default implementation ignores <paramref name="scheme" /> and calls <see cref="CreateIdentity(Type, object)" />.
        /// </remarks>
        IIdentity CreateIdentity(Type type, object payload, AuthenticationScheme scheme) =>
            CreateIdentity(type, payload);
    }
    
    /// <summary>
    /// Extension methods for <seealso cref="IIdentityFactory" />
    ///</summary>
    public static class IdentityFactoryExtensions
    {
        public static IIdentity CreateIdentity<T>(this IIdentityFactory factory, T payload) =>
            factory.CreateIdentity(typeof(T), payload);
    }
}