/*
   Reglas YARA propias de Atalaya.
   Detectan patrones de comportamiento en el contenido del binario, no familias
   concretas. El campo `puntos` alimenta directamente el motor de heuristicas.

   Requiere yara-python:  pip install yara-python
*/

rule Atalaya_PowerShell_Codificado
{
    meta:
        descripcion = "Contiene una invocacion de PowerShell con carga codificada"
        puntos = 45
        autor = "Atalaya"
    strings:
        $ps      = "powershell" nocase ascii wide
        $enc1    = "-EncodedCommand" nocase ascii wide
        $enc2    = " -enc " nocase ascii wide
        $enc3    = "FromBase64String" nocase ascii wide
        $hidden  = "-WindowStyle Hidden" nocase ascii wide
    condition:
        $ps and (2 of ($enc*, $hidden))
}

rule Atalaya_Descarga_Y_Ejecuta
{
    meta:
        descripcion = "Combina descarga desde red con ejecucion de proceso"
        puntos = 40
        autor = "Atalaya"
    strings:
        $d1 = "URLDownloadToFile" ascii
        $d2 = "InternetOpenUrl" ascii
        $d3 = "WinHttpSendRequest" ascii
        $d4 = "DownloadString" ascii wide nocase
        $e1 = "ShellExecute" ascii
        $e2 = "CreateProcess" ascii
        $e3 = "WinExec" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($d*) and 1 of ($e*)
}

rule Atalaya_Inyeccion_En_Proceso
{
    meta:
        descripcion = "Juego de APIs de inyeccion de codigo en proceso ajeno"
        puntos = 45
        autor = "Atalaya"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "NtUnmapViewOfSection" ascii
        $e = "QueueUserAPC" ascii
        $f = "SetThreadContext" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Atalaya_Registrador_De_Teclas
{
    meta:
        descripcion = "Patron compatible con registrador de pulsaciones"
        puntos = 40
        autor = "Atalaya"
    strings:
        $h1 = "SetWindowsHookEx" ascii
        $h2 = "GetAsyncKeyState" ascii
        $h3 = "GetKeyboardState" ascii
        $h4 = "GetForegroundWindow" ascii
        $w1 = "[ENTER]" ascii wide
        $w2 = "[BACKSPACE]" ascii wide
    condition:
        uint16(0) == 0x5A4D and (2 of ($h*) or any of ($w*))
}

rule Atalaya_Persistencia_Autonoma
{
    meta:
        descripcion = "El binario se escribe a si mismo en el arranque del sistema"
        puntos = 35
        autor = "Atalaya"
    strings:
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $r2 = "schtasks /create" ascii wide nocase
        $r3 = "SCManager" ascii
        $api1 = "RegSetValueEx" ascii
        $api2 = "CreateService" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of ($r*) and 1 of ($api*)
}

rule Atalaya_Evasion_Defensas
{
    meta:
        descripcion = "Manipula copias de seguridad, registro de eventos o antivirus"
        puntos = 55
        autor = "Atalaya"
    strings:
        $s1 = "vssadmin delete shadows" ascii wide nocase
        $s2 = "wbadmin delete catalog" ascii wide nocase
        $s3 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $s4 = "wevtutil cl" ascii wide nocase
        $s5 = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide nocase
        $s6 = "netsh advfirewall set allprofiles state off" ascii wide nocase
    condition:
        any of them
}

rule Atalaya_Antianalisis
{
    meta:
        descripcion = "Detecta maquina virtual o entorno de analisis antes de actuar"
        puntos = 30
        autor = "Atalaya"
    strings:
        $v1 = "VMware" ascii wide
        $v2 = "VBoxService" ascii wide
        $v3 = "vboxguest" ascii wide nocase
        $v4 = "SbieDll.dll" ascii wide
        $v5 = "wine_get_unix_file_name" ascii
        $d1 = "IsDebuggerPresent" ascii
        $d2 = "CheckRemoteDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($v*) and 1 of ($d*)
}

rule Atalaya_Nota_De_Rescate
{
    meta:
        descripcion = "Cadenas tipicas de una nota de rescate de ransomware"
        puntos = 60
        autor = "Atalaya"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "tus archivos han sido cifrados" ascii wide nocase
        $c = "to decrypt your files" ascii wide nocase
        $d = "bitcoin wallet" ascii wide nocase
        $e = ".onion" ascii wide nocase
    condition:
        2 of them
}
