using Owin;

namespace JWT
{
    public static class AppBuilderExtensions
    {
        public static void UseJwtMiddleware(this IAppBuilder appBuilder) =>
            appBuilder.Use<JwtAuthenticationMiddleware>();
    }
}