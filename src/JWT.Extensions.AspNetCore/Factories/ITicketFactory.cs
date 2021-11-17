using Microsoft.AspNetCore.Authentication;
using System.Security.Principal;

namespace JWT.Extensions.AspNetCore.Factories
{
    public interface ITicketFactory
    {
        AuthenticationTicket CreateTicket(IIdentity identity, AuthenticationScheme scheme);
    }
}