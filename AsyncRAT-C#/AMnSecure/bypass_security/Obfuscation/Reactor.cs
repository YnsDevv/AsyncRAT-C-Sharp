using System;
using System.Diagnostics;
using System.IO;

namespace AMnSecure.bypass_security.Obfuscation
{
    public class Reactor
    {
        public static // Destination (emplacement où copier le dossier)
            string NetReactorDirectory = Path.Combine(Directory.GetCurrentDirectory(), "NET_Reactor");

        public static void Run_NETReactor(string fileIn, string pathOut)
        {
            string commandsMinimum =
                " -embed 1 -obfuscate_public_types 1 -obfuscation 1 -debug 1 -control_flow 1 -flow_level 4 -stringencryption 1 -resourceencryption -resourcecompression max -virtualization 1 -necrobit 1 -targetfile ";
            string commandsFull =
                " -embed 1 -obfuscate_public_types 1 -obfuscation 1 -suppressildasm 1 -antitamp 1 -anti_debug 1 -hide_calls 1 -control_flow 1 -flow_level 9 -stringencryption 1 -resourceencryption 1 -resourcecompression max -virtualization 1 -necrobit 1 -targetfile ";
            Init();
            // Chemin vers l'exécutable dotNET_Reactor
            var reactorPath = Path.Combine(NetReactorDirectory, "dotNET_Reactor.exe");

            // Créez une string de commande pour transmettre l'entrée et la sortie
            var commandArgs = "-file " + fileIn +
                              commandsMinimum  +
                              pathOut + "";

            // Configurez le Process
            var processInfo = new ProcessStartInfo
            {
                FileName = reactorPath,
                Arguments = commandArgs,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = false
            };

            // Exécutez le Process et gérez les résultats
            using (var process = Process.Start(processInfo))
            {
                process.OutputDataReceived += (sender, args) =>
                {
                    if (!string.IsNullOrEmpty(args.Data))
                        Console.WriteLine(args.Data);
                };
                process.ErrorDataReceived += (sender, args) =>
                {
                    if (!string.IsNullOrEmpty(args.Data))
                        Console.WriteLine($"Error: {args.Data}");
                };
                
                process.WaitForExit();
                File.Delete(fileIn);
            }
        }

        public static void Init()
        {
            var pathDirectoryNetReactor = Directory.GetParent(Directory.GetCurrentDirectory())?.Parent?.FullName;
            // Ajouter le chemin relatif vers ".NET Reactor 6.9"
            var sourceDirectory = Path.Combine(pathDirectoryNetReactor ?? throw new InvalidOperationException(),
                ".NET Reactor 6.9");

            try
            {
                if (Directory.Exists(NetReactorDirectory))
                {
                    Console.WriteLine("Le dossier existe déja !");
                }
                else
                {
                    // Copier le dossier
                    CopyDirectory(sourceDirectory, NetReactorDirectory);
                    Console.WriteLine("Dossier copié avec succès !");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erreur lors de la copie : " + ex.Message);
            }
        }

        private static void CopyDirectory(string sourceDir, string destinationDir)
        {
            // Vérifier si le dossier source existe
            if (!Directory.Exists(sourceDir))
                throw new DirectoryNotFoundException($"Le dossier source n'existe pas : {sourceDir}");

            // Créer le dossier de destination s'il n'existe pas
            Directory.CreateDirectory(destinationDir);

            // Copier les fichiers du dossier source
            foreach (var filePath in Directory.GetFiles(sourceDir))
            {
                var destFile = Path.Combine(destinationDir, Path.GetFileName(filePath));
                File.Copy(filePath, destFile, true); // Copier et écraser si nécessaire
            }

            // Copier les sous-dossiers récursivement
            foreach (var dirPath in Directory.GetDirectories(sourceDir))
            {
                var destDir = Path.Combine(destinationDir, Path.GetFileName(dirPath));
                CopyDirectory(dirPath, destDir);
            }
        }
    }
}