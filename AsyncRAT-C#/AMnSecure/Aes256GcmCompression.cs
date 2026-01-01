using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace AMnSecure
{
    public class AesAdvancedCompression
    {
        private const int SaltSize = 32;
        private const int Iterations = 50000;
        private const int KeySize = 32;

        public static string EncryptBase64(byte[] payload, string password)
        {
            // Génération d'un sel plus grand pour plus de sécurité
            var salt = new byte[SaltSize];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            // Dérivation de clé renforcée
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                var key = keyDerivationFunction.GetBytes(KeySize);
                var additionalEntropy = keyDerivationFunction.GetBytes(16); // Entropie supplémentaire pour l'IV

                using (var aes = new AesManaged()) // AesManaged au lieu de RijndaelManaged
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = key;

                    // Génération d'IV avec entropie supplémentaire
                    using (var hmac = new HMACSHA256(additionalEntropy))
                    {
                        aes.IV = hmac.ComputeHash(salt).Take(16).ToArray();
                    }

                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    byte[] encryptedData;
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var cryptoStream =
                               new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        using (var hmacStream = new HMACSHA256(key)) // HMAC pour l'intégrité
                        {
                            cryptoStream.Write(payload, 0, payload.Length);
                            cryptoStream.FlushFinalBlock();
                            encryptedData = msEncrypt.ToArray();

                            // Calcul du HMAC sur les données chiffrées
                            var hmacValue = hmacStream.ComputeHash(encryptedData);

                            // Assemblage final : sel + IV + HMAC + données chiffrées
                            var result =
                                new byte[salt.Length + aes.IV.Length + hmacValue.Length + encryptedData.Length];
                            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                            Buffer.BlockCopy(aes.IV, 0, result, salt.Length, aes.IV.Length);
                            Buffer.BlockCopy(hmacValue, 0, result, salt.Length + aes.IV.Length, hmacValue.Length);
                            Buffer.BlockCopy(encryptedData, 0, result, salt.Length + aes.IV.Length + hmacValue.Length,
                                encryptedData.Length);

                            return Convert.ToBase64String(result);
                        }
                    }
                }
            }
        }

        public static byte[] Decrypt(string encryptedText, string password)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedText);

            if (encryptedBytes.Length < SaltSize + 16 + 32) // Vérification de la taille minimale
                throw new CryptographicException("Données chiffrées invalides");

            var salt = encryptedBytes.Take(SaltSize).ToArray();
            var iv = encryptedBytes.Skip(SaltSize).Take(16).ToArray();
            var hmacValue = encryptedBytes.Skip(SaltSize + 16).Take(32).ToArray();
            var cipherText = encryptedBytes.Skip(SaltSize + 16 + 32).ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                var key = keyDerivationFunction.GetBytes(KeySize);

                // Vérification de l'intégrité
                using (var hmac = new HMACSHA256(key))
                {
                    var computedHmac = hmac.ComputeHash(cipherText);
                    if (!computedHmac.SequenceEqual(hmacValue))
                        throw new CryptographicException("L'intégrité des données a été compromise");
                }

                using (var aes = new AesManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    try
                    {
                        using (var msDecrypt = new MemoryStream(cipherText))
                        using (var cryptoStream =
                               new CryptoStream(msDecrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        using (var resultStream = new MemoryStream())
                        {
                            cryptoStream.CopyTo(resultStream);
                            return resultStream.ToArray();
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        throw new CryptographicException(
                            "Échec du déchiffrement - Mot de passe incorrect ou données corrompues", ex);
                    }
                }
            }
        }

        // Méthodes de compression inchangées...
        public static byte[] Compress(byte[] data)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress, true))
                {
                    gzipStream.Write(data, 0, data.Length);
                }

                return memoryStream.ToArray();
            }
        }

        public static byte[] Decompress(byte[] compressedData)
        {
            using (var compressedStream = new MemoryStream(compressedData))
            using (var decompressedStream = new MemoryStream())
            using (var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            {
                gzipStream.CopyTo(decompressedStream);
                return decompressedStream.ToArray();
            }
        }
    }
}