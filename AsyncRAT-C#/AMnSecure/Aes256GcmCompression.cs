using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace AMnSecure
{
    public static class Aes256GcmCompression
    {
        private const int SaltSize = 32;        // PBKDF2 salt
        private const int Iterations = 50000;   // PBKDF2 iterations
        private const int KeySize = 32;         // 32 bytes = 256 bits
        private const int NonceSize = 12;       // GCM recommended nonce size
        private const int TagSize = 16;         // 16 bytes = 128-bit tag

        public static string EncryptBase64(byte[] payload, string password)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (password == null) throw new ArgumentNullException(nameof(password));

            byte[] salt = RandomBytes(SaltSize);
            byte[] key = DeriveKey(password, salt, Iterations, KeySize);

            byte[] nonce = RandomBytes(NonceSize);

            // AES-GCM: chiffrement + tag d'intégrité (pas besoin de HMAC séparé)
            var gcm = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
            var aeadParams = new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, associatedText: null);

            gcm.Init(true, aeadParams);

            byte[] cipherWithTag = new byte[gcm.GetOutputSize(payload.Length)];
            int len = gcm.ProcessBytes(payload, 0, payload.Length, cipherWithTag, 0);
            len += gcm.DoFinal(cipherWithTag, len);

            // BouncyCastle renvoie ciphertext||tag (tag à la fin)
            if (cipherWithTag.Length < TagSize)
                throw new CryptographicException("Sortie GCM invalide.");

            byte[] ciphertext = cipherWithTag.Take(cipherWithTag.Length - TagSize).ToArray();
            byte[] tag = cipherWithTag.Skip(cipherWithTag.Length - TagSize).ToArray();

            // Assemblage final : salt + nonce + tag + ciphertext
            byte[] result = new byte[salt.Length + nonce.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, result, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, result, salt.Length + nonce.Length + tag.Length, ciphertext.Length);

            return Convert.ToBase64String(result);
        }

        public static byte[] Decrypt(string encryptedText, string password)
        {
            if (encryptedText == null) throw new ArgumentNullException(nameof(encryptedText));
            if (password == null) throw new ArgumentNullException(nameof(password));

            byte[] data = Convert.FromBase64String(encryptedText);

            int minLen = SaltSize + NonceSize + TagSize + 1;
            if (data.Length < minLen)
                throw new CryptographicException("Données chiffrées invalides (trop courtes).");

            byte[] salt = data.Take(SaltSize).ToArray();
            byte[] nonce = data.Skip(SaltSize).Take(NonceSize).ToArray();
            byte[] tag = data.Skip(SaltSize + NonceSize).Take(TagSize).ToArray();
            byte[] ciphertext = data.Skip(SaltSize + NonceSize + TagSize).ToArray();

            byte[] key = DeriveKey(password, salt, Iterations, KeySize);

            // Pour déchiffrer avec BouncyCastle, on redonne ciphertext||tag
            byte[] cipherWithTag = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, cipherWithTag, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, cipherWithTag, ciphertext.Length, tag.Length);

            try
            {
                var gcm = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
                var aeadParams = new AeadParameters(new KeyParameter(key), TagSize * 8, nonce, associatedText: null);

                gcm.Init(false, aeadParams);

                byte[] plaintext = new byte[gcm.GetOutputSize(cipherWithTag.Length)];
                int len = gcm.ProcessBytes(cipherWithTag, 0, cipherWithTag.Length, plaintext, 0);
                len += gcm.DoFinal(plaintext, len);

                // Ajuster à la taille réelle
                if (len != plaintext.Length)
                    Array.Resize(ref plaintext, len);

                return plaintext;
            }
            catch (Exception ex)
            {
                // Typiquement: mauvais password OU données modifiées (tag invalide)
                throw new CryptographicException("Échec du déchiffrement (mot de passe incorrect ou données corrompues).", ex);
            }
        }

        // Optionnel : compression comme ton exemple (GZip)
        public static byte[] Compress(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            using (var ms = new MemoryStream())
            {
                using (var gzip = new GZipStream(ms, CompressionMode.Compress, true))
                {
                    gzip.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }

        public static byte[] Decompress(byte[] compressedData)
        {
            if (compressedData == null) throw new ArgumentNullException(nameof(compressedData));

            using (var input = new MemoryStream(compressedData))
            using (var output = new MemoryStream())
            using (var gzip = new GZipStream(input, CompressionMode.Decompress))
            {
                gzip.CopyTo(output);
                return output.ToArray();
            }
        }

        private static byte[] DeriveKey(string password, byte[] salt, int iterations, int keyBytes)
        {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations))
                return kdf.GetBytes(keyBytes);
        }

        private static byte[] RandomBytes(int count)
        {
            var bytes = new byte[count];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(bytes);
            return bytes;
        }
    }
}