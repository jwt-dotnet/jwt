using Microsoft.AspNetCore.Authentication;
using System.Security.Principal;

namespace JWT.Factory
{
    public interface ITicketFactory
    {
        AuthenticationTicket CreateTicket(IIdentity identity, AuthenticationScheme scheme);
    }
}