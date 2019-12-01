// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

using System;
using JWT.Algorithms;
using Microsoft.AspNetCore.Authentication;

namespace JWT
{
    public class JwtAuthenticationOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// The keys provided which one of them was used to sign the JWT.
        /// </summary>
        /// <remarks>
        /// This property is optional when <see cref="RS256Algorithm" /> is used.
        /// </remarks>
        public string[] Keys { get; set; }

        /// <summary>
        /// The flag whether to verify the signature or not. The default value is <see cref="Boolean.TrueString" />.
        /// </summary>
        public bool VerifySignature { get; set; } = true;
    }
}