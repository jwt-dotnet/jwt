namespace JWT.Extensions.AspNetCore;

using System;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

public class FailedTicketContext
{
    public FailedTicketContext(ILogger logger, Exception exception, HttpContext context, JwtAuthenticationOptions options)
    {
        this.Logger = logger;
        this.Exception = exception;
        this.Context = context;
        this.Options = options;
    }

    public ILogger Logger { get; }
    public Exception Exception { get; }
    public HttpContext Context { get; }
    public JwtAuthenticationOptions Options { get; }
}