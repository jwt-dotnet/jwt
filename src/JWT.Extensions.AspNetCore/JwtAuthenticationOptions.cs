// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

using Microsoft.AspNetCore.Authentication;

namespace JWT
{
    public class JwtAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Key { get; set; }

        public bool Verify { get; set; } = true;
    }
}