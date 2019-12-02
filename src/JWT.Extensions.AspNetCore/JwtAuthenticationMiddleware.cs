// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

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
            throw new NotImplementedException("TODO");

            await _next.Invoke(context);
        }
    }
}