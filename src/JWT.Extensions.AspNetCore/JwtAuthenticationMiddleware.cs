// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace JWT
{
    public abstract class JwtAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        protected JwtAuthenticationMiddleware(RequestDelegate next) =>
            _next = next;

        public async Task Invoke(HttpContext context)
        {
            // Give child class a chance to handle the request
            if (!await AuthenticateRequestAsync(context))
                await _next.Invoke(context);
        }

        protected virtual Task<bool> AuthenticateRequestAsync(HttpContext context) =>
            Task.FromResult(false);
    }
}