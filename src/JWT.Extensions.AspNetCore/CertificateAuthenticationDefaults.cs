// Copyright (c) Alexander Batishchev. All rights reserved.
// Licensed under the MIT License. See License.md in the project root for license information.

namespace JWT
{
    /// <summary>
    /// Default values related to Jwt authentication/authorization
    /// </summary>
    public static class JwtAuthenticationDefaults
    {
        /// <summary>
        /// The default value used for <see cref="JwtAuthenticationOptions" />.
        /// </summary>
        public const string AuthenticationScheme = "Bearer";
    }
}