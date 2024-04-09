namespace JWT.Extensions.AspNetCore;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

public class SuccessfulTicketContext
{
    public SuccessfulTicketContext(ILogger logger, AuthenticationTicket ticket, HttpContext context, JwtAuthenticationOptions options)
    {
        this.Logger = logger;
        this.Ticket = ticket;
        this.Context = context;
        this.Options = options;
    }

    public ILogger Logger { get; }
    public AuthenticationTicket Ticket { get; }
    public HttpContext Context { get; }
    public JwtAuthenticationOptions Options { get; }
}