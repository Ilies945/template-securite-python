rule TP2_Test_File
{
    meta:
        description = "Detection du fichier de test TP2"
    strings:
        $message = "Ceci est un fichier de test TP2"
    condition:
        $message
}

rule TP2_Suspicious_Commands
{
    meta:
        description = "Recherche de commandes potentiellement suspectes"
    strings:
        $cmd1 = "powershell" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "wget " nocase
    condition:
        any of them
}
