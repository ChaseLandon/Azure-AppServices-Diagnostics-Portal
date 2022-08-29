using Backend.Models;
using Microsoft.ApplicationInsights;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Backend.Services
{
    public class EncryptionService : IEncryptionService
    {
        private readonly CertificateService _certificateRefreshService;
        private readonly string _encryptionKey;
        private TelemetryClient _telemetryClient;

        public EncryptionService(IServiceProvider serviceProvider, IConfiguration configuration, TelemetryClient telemetryClient)
        {
            _certificateRefreshService = serviceProvider.GetService<CertificateService>();
            _encryptionKey = configuration["AppInsights:EncryptionKey"];
            _telemetryClient = telemetryClient;
        }

        public string EncryptString(string apiKey)
        {
            X509Certificate2? certificate = _certificateRefreshService.GetCertificate();
            using var rsa = certificate.GetRSAPublicKey();
            var byteArray = rsa.Encrypt(Encoding.UTF8.GetBytes(apiKey), RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(byteArray);
        }

        public AppInsightsDecryptionResponse DecryptString(string encryptedString)
        {
            var response = new AppInsightsDecryptionResponse();
            var data = Convert.FromBase64String(encryptedString);
            X509Certificate2? cert = _certificateRefreshService.GetCertificate();

            //
            // Try decrypting the hash using the current certificate. If this succeeds,
            // then we have the hash encrypted using latest and we are good
            //

            string apiKey = DecryptUsingCertificate(cert, data);
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                response.ApiKey = apiKey;
                return response;
            }

            //
            // If the current certificate fails, then try decrypting using the expired certs
            //

            foreach (var expiredCert in _certificateRefreshService.GetExpiredCertificates())
            {
                apiKey = DecryptUsingCertificate(cert, data);
                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    response.ApiKey = apiKey;
                    response.UsingExpiredKeyOrCertificate = true;
                    break;
                }
            }

            //
            // If we fail to decrypt using all certs, try decrypting using the legacy
            // encryption technique. This should go away in a few months.
            //

            if (string.IsNullOrWhiteSpace(response.ApiKey))
            {
                response.UsingExpiredKeyOrCertificate = true;
                response.ApiKey = DecryptStringLegacy(encryptedString);
            }

            return response;
        }

        private string DecryptStringLegacy(string encryptedString)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(encryptedString);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(_encryptionKey);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        private string DecryptUsingCertificate(X509Certificate2? cert, byte[]? data)
        {
            if (cert == null)
            {
                throw new Exception("Failed to load the certificate to decrypt");
            }

            _telemetryClient.TrackTrace($"Trying to decrypt data using {cert.Thumbprint} {cert.Subject}");
            using var rsa = cert.GetRSAPrivateKey();
            try
            {
                var byteArray = rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
                _telemetryClient.TrackTrace($"Decrypted data successfully using {cert.Thumbprint} {cert.Subject}");
                return Encoding.UTF8.GetString(byteArray);
            }
            catch (Exception ex)
            {
                _telemetryClient.TrackTrace($"Failed to decrypt using certificate {cert.Thumbprint} {cert.Subject}", 
                    new Dictionary<string, string>()
                    {
                        {"exceptionMessage", ex.Message}
                    }
                );
            }

            return string.Empty;
        }
    }
}
