using Microsoft.AspNetCore.Authentication;
using System.Security.Principal;

namespace JWT
{
    public interface ITicketFactory
    {
        AuthenticationTicket CreateTicket(IIdentity identity, AuthenticationScheme scheme);
    }
}