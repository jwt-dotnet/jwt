using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace JWT
{
    public sealed class JwtAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtAuthenticationMiddleware(RequestDelegate next) =>
            _next = next;

        public async Task Invoke(HttpContext context)
        {
            throw new NotImplementedException("TBD");

            await _next.Invoke(context);
        }
    }
}