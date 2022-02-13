using System;
using System.Security.Principal;

namespace JWT.Extensions.AspNetCore.Factories
{
    public interface IIdentityFactory
    {
        /// <summary>
        /// Creates <see cref="IIdentity" /> from the payload of the specified type.
        /// </summary>
        IIdentity CreateIdentity(Type type, object payload);
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