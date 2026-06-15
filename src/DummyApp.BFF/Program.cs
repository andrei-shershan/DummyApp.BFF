using Azure.Identity;
using DummyApp.BFF.Configuration;
using DummyApp.BFF.Extensions;

var builder = WebApplication.CreateBuilder(args);
var configurationSettings = builder.Configuration.Get<ConfigurationSettings>() ?? new ConfigurationSettings();

// Key Vault: add in stg/prod only; local dev uses appsettings.Development.json
if (!builder.Environment.IsDevelopment())
{
    var keyVaultUrl = configurationSettings.KeyVault.Url;
    if (!string.IsNullOrEmpty(keyVaultUrl))
    {
        var clientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
        var credential = string.IsNullOrEmpty(clientId)
            ? new ManagedIdentityCredential()
            : new ManagedIdentityCredential(clientId);

        builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUrl), credential);
    }
}

builder.AddBffServices();

var app = builder.Build();
app.UseBff();
app.Run();
