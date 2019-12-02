using System;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace JWT
{
    public sealed class JwtAuthenticationMiddleware : OwinMiddleware
    {
        public JwtAuthenticationMiddleware(OwinMiddleware next)
            : base(next)
        {
        }

        public override async Task Invoke(IOwinContext context)
        {
            throw new NotImplementedException("TBD");

            await this.Next.Invoke(context);
        }
    }
}