namespace JwtAuthDotNet.Models
{
    public class ResponseTokenDto
    {
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
    }
}
