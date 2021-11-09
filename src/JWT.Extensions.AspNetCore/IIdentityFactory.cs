using System.Collections.Generic;
using System.Security.Principal;

namespace JWT
{
    public interface IIdentityFactory
    {
        IIdentity CreateIdentity(IDictionary<string, string> payload);
    }
}