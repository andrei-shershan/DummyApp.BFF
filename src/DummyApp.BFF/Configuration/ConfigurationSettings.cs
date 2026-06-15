namespace DummyApp.BFF.Configuration
{
    public class ConfigurationSettings
    {
        public KeyVaultSettings KeyVault { get; set; } = new();
        public CorsSettings Cors { get; set; } = new();
        public IdentityServerSettings IdentityServer { get; set; } = new();
        public ServiceSettings Services { get; set; } = new();
        public ReverseProxySettings ReverseProxy { get; set; } = new();

        public class KeyVaultSettings
        {
            public string Url { get; set; } = string.Empty;
        }

        public class CorsSettings
        {
            public string[] AllowedOrigins { get; set; } = Array.Empty<string>();
        }

        public class IdentityServerSettings
        {
            public string Authority { get; set; } = string.Empty;
            public OidcClientsSettings OidcClients { get; set; } = new();
            public string? MetadataAddress { get; set; }
        }

        public class OidcClientsSettings
        {
            public BffClientSettings BFF { get; set; } = new();
        }

        public class BffClientSettings
        {
            public string ClientId { get; set; } = string.Empty;
            public string ClientSecret { get; set; } = string.Empty;
            public string? TokenEndpoint { get; set; }
        }

        public class ServiceSettings
        {
            public FrontendSettings Frontend { get; set; } = new();
        }

        public class FrontendSettings
        {
            public string BaseUrl { get; set; } = string.Empty;
        }

        public class ReverseProxySettings
        {
            public bool TrustAllProxies { get; set; }
        }
    }
}
