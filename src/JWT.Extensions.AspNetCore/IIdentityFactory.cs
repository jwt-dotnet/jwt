using System.Collections.Generic;
using System.Security.Principal;

namespace JWT
{
    internal interface IIdentityFactory
    {
        IIdentity CreateIdentity(IDictionary<string, string> payload);
    }
}