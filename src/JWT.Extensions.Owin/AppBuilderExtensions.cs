using Owin;

namespace JWT
{
    public static class AppBuilderExtensions
    {
        public static void UseClientCertificateAuthentication(this IAppBuilder appBuilder) =>
            appBuilder.Use<JwtAuthenticationMiddleware>();
    }
}