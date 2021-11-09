using System.Collections.Generic;
using System.Security.Principal;

namespace JWT.Extensions.AspNetCore.Factories
{
    public interface IIdentityFactory
    {
        IIdentity CreateIdentity(IDictionary<string, string> payload);
    }
}