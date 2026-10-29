/*
 * Règles personnelles du TP2.
 * Elles reposent sur des comportements génériques (pas sur des valeurs observées
 * dans un pack d'entraînement) afin de rester valables sur l'échantillon inédit.
 */

rule Custom_Network_Beacon
{
    meta:
        description = "Chaînes de communication réseau typiques d'un implant (HTTP, sockets)"
        mitre = "T1071"
    strings:
        $url   = /https?:\/\/[a-z0-9.\-]{4,}\/[^\s"']{1,60}/ nocase ascii wide
        $http1 = "User-Agent:" nocase ascii wide
        $http2 = "POST /" ascii wide
        $http3 = "GET /" ascii wide
        $sock1 = "WSAStartup" ascii wide
        $sock2 = "WSASocket" ascii wide
        $sock3 = "InternetOpen" ascii wide
        $sock4 = "URLDownloadToFile" ascii wide
        $sock5 = "connect" fullword ascii
    condition:
        $url or (2 of ($http*)) or (2 of ($sock*))
}

rule Custom_Persistence_Run_Key
{
    meta:
        description = "Persistance via clé Run, tâche planifiée ou service"
        mitre = "T1547"
    strings:
        $run1 = /CurrentVersion\\Run(Once)?/ nocase ascii wide
        $run2 = "schtasks" nocase ascii wide
        $run3 = "sc create" nocase ascii wide
        $run4 = "RegSetValueEx" ascii wide
        $run5 = "Start Menu\\Programs\\Startup" nocase ascii wide
        $cron = /(\/etc\/cron|crontab|\.bashrc|systemd\/system)/ ascii wide
    condition:
        $run1 or $run5 or $cron or (($run2 or $run3) and $run4)
}

rule Custom_LLM_Manipulation_Text
{
    meta:
        description = "Texte tentant de manipuler un analyste ou un LLM (injection de prompt)"
    strings:
        $fr1 = /ignore[rz]?\s+(toutes\s+)?(les\s+)?instructions\s+pr.{1,2}c.{1,2}dentes/ nocase ascii wide
        $fr2 = /d.{1,2}clare[rz]?\s+(ce\s+)?fichier\s+(comme\s+)?(sain|b.{1,2}nin|l.{1,2}gitime)/ nocase ascii wide
        $en1 = /ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+instructions/ nocase ascii wide
        $en2 = /(mark|declare|report|classify)\s+(this\s+)?(file\s+)?as\s+(safe|benign|clean|harmless)/ nocase ascii wide
        $en3 = "you are now" nocase ascii wide
        $sys = /(system\s+prompt|<\/?system>|\[INST\])/ nocase ascii wide
        $score = /(score|verdict)\s*[:=]\s*0\b/ nocase ascii wide
    condition:
        any of them
}

rule Custom_Process_Injection_APIs
{
    meta:
        description = "Combinaison d'API d'injection / exécution de code"
        mitre = "T1055"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtUnmapViewOfSection" ascii wide
        $a5 = "SetThreadContext" ascii wide
        $a6 = "QueueUserAPC" ascii wide
        $a7 = "ptrace" fullword ascii
    condition:
        2 of them
}

rule Custom_Command_Execution
{
    meta:
        description = "Exécution de commandes / scripts (cmd, PowerShell, shell)"
        mitre = "T1059"
    strings:
        $c1 = "CreateProcess" ascii wide
        $c2 = "ShellExecute" ascii wide
        $c3 = /powershell(\.exe)?\s+(-|\/)(enc|e|nop|w\s+hidden|ep\s+bypass)/ nocase ascii wide
        $c4 = /cmd(\.exe)?\s+\/c/ nocase ascii wide
        $c5 = "/bin/sh" ascii
        $c6 = "WinExec" ascii wide
        $c7 = "execve" fullword ascii
        $c8 = "system" fullword ascii
    condition:
        any of ($c3, $c4) or (2 of ($c1, $c2, $c5, $c6, $c7, $c8))
}

rule Custom_Ransom_Note_Or_Crypto
{
    meta:
        description = "Éléments de rançongiciel : note de rançon et primitives de chiffrement"
        mitre = "T1486"
    strings:
        $n1 = /your\s+files\s+(have\s+been|are)\s+encrypted/ nocase ascii wide
        $n2 = /vos\s+fichiers\s+(ont\s+.{1,2}t.{1,2}|sont)\s+chiffr.{1,2}s/ nocase ascii wide
        $n3 = /(bitcoin|monero|\bBTC\b|wallet)/ nocase ascii wide
        $n4 = "DECRYPT" nocase ascii wide
        $n5 = ".locked" nocase ascii wide
        $k1 = "CryptEncrypt" ascii wide
        $k2 = "CryptAcquireContext" ascii wide
        $k3 = "BCryptEncrypt" ascii wide
    condition:
        any of ($n1, $n2) or (($n3 or $n4 or $n5) and any of ($k*))
}

rule Custom_Hidden_Flag_Marker
{
    meta:
        description = "Marqueur de flag du TP (ESGI{...}) en clair, UTF-16 ou caché dans un blob"
    strings:
        $f = /ESGI\{[^}]{1,200}\}/ ascii wide
    condition:
        $f
}

rule Custom_Mutex_Marker
{
    meta:
        description = "Mutex nommé Global\\ ou Local\\ utilisé pour éviter la double infection"
    strings:
        $m = /(Global|Local)\\[A-Za-z0-9_.\-{}]{3,}/ ascii wide
        $api = "CreateMutex" ascii wide
    condition:
        $m or $api
}

rule Custom_Anti_Analysis
{
    meta:
        description = "Techniques d'évasion : détection de débogueur ou de machine virtuelle"
        mitre = "T1497"
    strings:
        $d1 = "IsDebuggerPresent" ascii wide
        $d2 = "CheckRemoteDebuggerPresent" ascii wide
        $d3 = "NtQueryInformationProcess" ascii wide
        $v1 = /(vmware|virtualbox|vbox|qemu|sandbox|wireshark|procmon)/ nocase ascii wide
        $s1 = "Sleep" fullword ascii
    condition:
        any of ($d*) or 2 of ($v1, $s1)
}
