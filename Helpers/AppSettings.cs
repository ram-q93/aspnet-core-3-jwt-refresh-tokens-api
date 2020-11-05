namespace WebApi.Helpers
{
    public class AppSettings
    {
        public string Secret { get; set; }
        public int TokenExpiresInMinutes{ get; set; }
        public int RefreshTokenExpiresInMinutes { get; set; }

    }
}