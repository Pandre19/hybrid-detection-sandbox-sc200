<#
.SYNOPSIS
    MITRE ATT&CK T1059.001 - Command and Control (C2) via DNS Beaconing Simulation.
.DESCRIPTION
    This script simulates a DNS-based command and control beaconing behavior. 
    It generates periodic DNS TXT queries using randomized subdomains to mimic data exfiltration 
    and heartbeat traffic, flooding the local DNS cache and generating telemetry for Microsoft Sentinel.
.AUTHOR
    Jerry André Peña Alfaro
#>

# --- Configuration Parameters / Parámetros de Configuración ---
param(
    [string]$Domain = "microsoft.com",         # Target domain to append / Dominio objetivo
    [string]$Subdomain = "subdomain",         # Base C2 channel indicator
    [string]$Sub2domain = "sub2domain",       # Secondary C2 beacon
    [string]$Sub3domain = "sub3domain",       # Exfiltration channel simulation
    [string]$QueryType = "TXT",               # Common query type used by DNS malware / Tipo de query común en malware DNS
    [int]$C2Interval = 8,                     # Base heartbeat interval in seconds / Intervalo base en segundos
    [int]$C2Jitter = 20,                      # Jitter percentage to evade threshold detections / Porcentaje de variación para evadir umbrales
    [int]$RunTime = 240                       # Total execution time in minutes (4 hours) / Tiempo total de ejecución
)

$RunStart = Get-Date
$RunEnd = $RunStart.addminutes($RunTime)
$x2 = 1
$x3 = 1 

Write-Host "[+] Adversary Emulation Started: DNS Beaconing active for $RunTime minutes." -ForegroundColor Cyan
Write-Host "[!] Telemetry generation in progress... Check your Sentinel SecurityEvent/Event tables." -ForegroundColor Yellow

# --- Main Simulation Loop / Bucle Principal de Simulación ---
Do {
    $TimeNow = Get-Date
    
    # 1. Primary Beaconing: Generates standard heartbeat packets with pseudo-random subdomains
    # Cacería Primaria: Genera latidos estándar con subdominios pseudo-aleatorios
    $RandomID = Get-Random -Minimum 1 -Maximum 999999
    $TargetQuery = "$Subdomain.$RandomID.$Domain"
    
    # Execute DNS resolution (Will trigger NXDOMAIN logs in environment, which is intended)
    # Ejecuta la resolución (Gatillará errores NXDOMAIN en el entorno, lo cual es el objetivo)
    Resolve-DnsName -type $QueryType $TargetQuery -QuickTimeout > $null 2>&1
    
    # 2. Secondary Beaconing Cycle (Simulates periodic task checking every 3 iterations)
    # Ciclo Secundario: Simula verificación de tareas periódicas cada 3 iteraciones
    if ($x2 -eq 3 )
    {
        $RandomID2 = Get-Random -Minimum 1 -Maximum 999999
        Resolve-DnsName -type $QueryType "$Sub2domain.$RandomID2.$Domain" -QuickTimeout > $null 2>&1
        $x2 = 1
    }
    else
    {
        $x2 = $x2 + 1
    }    
    
    # 3. Data Exfiltration Simulation Cycle (Simulates slow data staging every 7 iterations)
    # Ciclo de Exfiltración: Simula empaquetado lento de datos cada 7 iteraciones
    if ($x3 -eq 7 )
    {
        $RandomID3 = Get-Random -Minimum 1 -Maximum 999999
        Resolve-DnsName -type $QueryType "$Sub3domain.$RandomID3.$Domain" -QuickTimeout > $null 2>&1
        $x3 = 1
    }
    else
    {
        $x3 = $x3 + 1
    }
    
    # --- Jitter Calculation / Cálculo de Jitter (Evadir Detecciones de Umbral) ---
    # Real-world malware randomizes sleep times to avoid look like a rigid machine loop.
    # El malware real varía los tiempos de espera para no parecer un bucle rígido automatizado.
    $Jitter = ((Get-Random -Minimum -$C2Jitter -Maximum $C2Jitter) / 100 + 1) + $C2Interval
    
    Write-Host "[*] Beacon sent to $TargetQuery. Sleeping for $Jitter seconds..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $Jitter
}
Until ($TimeNow -ge $RunEnd)

Write-Host "[+] Adversary Emulation Completed successfully." -ForegroundColor Green