#Requires -Version 5.1
<#
    RigWarden - el guardián de tu PC
    Herramienta para revisar qué arranca con Windows, comprobar la seguridad del equipo
    y deshacer cualquier cambio. Pensada para usuarios sin conocimientos técnicos.

    Uso (PowerShell):
        irm https://raw.githubusercontent.com/USUARIO/rigwarden/main/RigWarden.ps1 | iex

    Versión 0.1: Inicio automático · Procesos · Seguridad · Deshacer
#>

# ----------------------------------------------------------------------------------------------
#  Configuración
# ----------------------------------------------------------------------------------------------
$AppName    = 'RigWarden'
$AppVersion = '0.1.0'
# Cambia USUARIO por tu nombre de usuario de GitHub:
$RepoRawUrl = 'https://raw.githubusercontent.com/USUARIO/rigwarden/main/RigWarden.ps1'

# ----------------------------------------------------------------------------------------------
#  Si se ejecuta como archivo en Windows PowerShell 5.1, se vuelve a cargar leyendo el archivo
#  como UTF-8 para que las tildes se vean bien.
# ----------------------------------------------------------------------------------------------
if ($PSCommandPath -and -not $env:RIGWARDEN_UTF8 -and $PSVersionTable.PSVersion.Major -lt 6) {
    $env:RIGWARDEN_UTF8 = '1'
    try { Invoke-Expression ([IO.File]::ReadAllText($PSCommandPath, [Text.Encoding]::UTF8)) }
    finally { Remove-Item Env:RIGWARDEN_UTF8 -ErrorAction SilentlyContinue }
    return
}

# ----------------------------------------------------------------------------------------------
#  Rutas de datos
# ----------------------------------------------------------------------------------------------
$script:DataDir    = Join-Path $env:ProgramData 'RigWarden'
$script:BackupDir  = Join-Path $script:DataDir 'Copias'
$script:LogFile    = Join-Path $script:DataDir 'cambios.json'
$script:ReviewFile = Join-Path $script:DataDir 'revisados.json'

$script:SigCache       = @{}
$script:AutoList       = @()
$script:AutoById       = @{}
$script:ProcList       = @()
$script:ProcById       = @{}
$script:SecList        = @()
$script:SecById        = @{}
$script:Reviewed       = New-Object 'System.Collections.Generic.HashSet[string]'
$script:RestoreChecked = $false
$script:UI             = @{}

$script:Interpreters = @('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe',
    'python.exe','pythonw.exe','py.exe','pyw.exe','rundll32.exe','regsvr32.exe','conhost.exe','node.exe',
    'java.exe','javaw.exe','msiexec.exe','bash.exe','wsl.exe')
$script:QuietInterpretersForProcesses = @('cmd.exe','conhost.exe','rundll32.exe','powershell.exe','pwsh.exe',
    'regsvr32.exe','msiexec.exe','node.exe','java.exe','javaw.exe')
$script:SystemNames = @('svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe','explorer.exe',
    'smss.exe','dllhost.exe','taskhostw.exe','runtimebroker.exe','spoolsv.exe','wininit.exe','sihost.exe',
    'ctfmon.exe','lsm.exe','audiodg.exe','dwm.exe','fontdrvhost.exe','searchindexer.exe')
$script:StrongPatterns = @(
    @{ P = '\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}'; N = 'Alto';  T = 'Usa un comando de PowerShell codificado (escondido). Es una técnica muy típica del malware.' },
    @{ P = 'frombase64string';                            N = 'Alto';  T = 'Descodifica datos escondidos (Base64) al ejecutarse.' },
    @{ P = 'downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|\birm\b|net\.webclient|bitsadmin|certutil.+urlcache|start-bitstransfer'; N = 'Alto'; T = 'Descarga cosas de internet cada vez que se ejecuta.' },
    @{ P = '\biex\b|invoke-expression';                   N = 'Alto';  T = 'Ejecuta código que no está guardado en ningún archivo (Invoke-Expression).' },
    @{ P = '-w(indowstyle)?\s+h(id|idden)\b|--headless';  N = 'Alto';  T = 'Se abre en una ventana oculta para que no lo veas.' },
    @{ P = 'add-mppreference|set-mppreference';           N = 'Alto';  T = 'Modifica la configuración del antivirus (Microsoft Defender).' },
    @{ P = 'https?://';                                   N = 'Medio'; T = 'Contiene una dirección de internet.' }
)

# ----------------------------------------------------------------------------------------------
#  Utilidades generales
# ----------------------------------------------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-DataDir {
    foreach ($d in @($script:DataDir, $script:BackupDir)) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
}

function Read-JsonList([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $raw = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        return @($raw | ConvertFrom-Json)
    } catch { return @() }
}

function Save-JsonList([string]$Path, $Items) {
    $json = ConvertTo-Json -InputObject @($Items) -Depth 8
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Get-ShortHash([string]$Text) {
    $sha = [Security.Cryptography.SHA1]::Create()
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
    return (([BitConverter]::ToString($bytes)) -replace '-', '').Substring(0, 16)
}

function Test-FileQuiet([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [IO.File]::Exists($Path) } catch { return $false }
}

function Get-Timestamp { return (Get-Date).ToString('yyyyMMdd-HHmmss') }

function Load-Reviewed {
    $script:Reviewed.Clear()
    foreach ($id in (Read-JsonList $script:ReviewFile)) { if ($id) { [void]$script:Reviewed.Add([string]$id) } }
}

function Save-Reviewed {
    Save-JsonList $script:ReviewFile @($script:Reviewed)
}

# ----------------------------------------------------------------------------------------------
#  Registro de cambios (para poder deshacer)
# ----------------------------------------------------------------------------------------------
function Add-ChangeLog([string]$Modulo, [string]$Descripcion, [string]$Tipo, $Datos) {
    $log = @(Read-JsonList $script:LogFile)
    $entry = [pscustomobject]@{
        Id          = [guid]::NewGuid().ToString()
        Fecha       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Modulo      = $Modulo
        Descripcion = $Descripcion
        Tipo        = $Tipo
        Datos       = $Datos
        Deshecho    = $false
    }
    $log += $entry
    Save-JsonList $script:LogFile $log
}

function Get-RegValueBackup([string]$KeyPath, [string]$Name) {
    $result = [ordered]@{ Existe = $false; Tipo = ''; Datos = $null }
    try {
        if (-not (Test-Path -LiteralPath $KeyPath)) { return $result }
        $key = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
        if (-not ($key.GetValueNames() -contains $Name)) { return $result }
        $kind = $key.GetValueKind($Name).ToString()
        $val  = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
        if ($kind -eq 'Binary') { $val = [Convert]::ToBase64String([byte[]]$val) }
        $result.Existe = $true; $result.Tipo = $kind; $result.Datos = $val
    } catch { }
    return $result
}

function Restore-RegValue([string]$KeyPath, [string]$Name, $Backup) {
    if (-not $Backup.Existe) {
        Remove-ItemProperty -LiteralPath $KeyPath -Name $Name -ErrorAction SilentlyContinue
        return
    }
    if (-not (Test-Path -LiteralPath $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    switch ($Backup.Tipo) {
        'Binary'      { $v = [Convert]::FromBase64String([string]$Backup.Datos) }
        'MultiString' { $v = [string[]]@($Backup.Datos) }
        'DWord'       { $v = [int]$Backup.Datos }
        'QWord'       { $v = [long]$Backup.Datos }
        default       { $v = [string]$Backup.Datos }
    }
    New-ItemProperty -LiteralPath $KeyPath -Name $Name -Value $v -PropertyType $Backup.Tipo -Force | Out-Null
}

function Set-RegValueLogged([string]$Modulo, [string]$Descripcion, [string]$KeyPath, [string]$Name, $Value, [string]$Kind) {
    $bk = Get-RegValueBackup $KeyPath $Name
    if (-not (Test-Path -LiteralPath $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    New-ItemProperty -LiteralPath $KeyPath -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
    Add-ChangeLog $Modulo $Descripcion 'RegValor' @{ Key = $KeyPath; Name = $Name; Backup = $bk }
}

function Remove-RegValueLogged([string]$Modulo, [string]$Descripcion, [string]$KeyPath, [string]$Name) {
    $bk = Get-RegValueBackup $KeyPath $Name
    Remove-ItemProperty -LiteralPath $KeyPath -Name $Name -ErrorAction Stop
    Add-ChangeLog $Modulo $Descripcion 'RegValor' @{ Key = $KeyPath; Name = $Name; Backup = $bk }
}

$script:ReversibleTypes = @('RegValor','Archivo','TareaEstado','TareaEliminada','ServicioEliminado','Exclusion','Firewall')

function Undo-Change($Change) {
    $d = $Change.Datos
    switch ($Change.Tipo) {
        'RegValor'          { Restore-RegValue $d.Key $d.Name $d.Backup }
        'Archivo'           { Move-Item -LiteralPath $d.Copia -Destination $d.Origen -Force -ErrorAction Stop }
        'TareaEstado'       {
            if ($d.EstabaActiva) { Enable-ScheduledTask -TaskName $d.TaskName -TaskPath $d.TaskPath -ErrorAction Stop | Out-Null }
            else                 { Disable-ScheduledTask -TaskName $d.TaskName -TaskPath $d.TaskPath -ErrorAction Stop | Out-Null }
        }
        'TareaEliminada'    {
            $xml = [IO.File]::ReadAllText($d.Xml)
            Register-ScheduledTask -Xml $xml -TaskName $d.TaskName -TaskPath $d.TaskPath -Force -ErrorAction Stop | Out-Null
        }
        'ServicioEliminado' { & reg.exe import $d.RegFile 2>&1 | Out-Null }
        'Exclusion'         {
            switch ($d.Clase) {
                'Path'      { Add-MpPreference -ExclusionPath $d.Valor -ErrorAction Stop }
                'Process'   { Add-MpPreference -ExclusionProcess $d.Valor -ErrorAction Stop }
                'Extension' { Add-MpPreference -ExclusionExtension $d.Valor -ErrorAction Stop }
            }
        }
        'Firewall'          { Set-NetFirewallProfile -Name $d.Perfil -Enabled False -ErrorAction Stop }
        default             { throw 'Este cambio no se puede deshacer automáticamente.' }
    }
    $log = @(Read-JsonList $script:LogFile)
    foreach ($c in $log) { if ($c.Id -eq $Change.Id) { $c.Deshecho = $true } }
    Save-JsonList $script:LogFile $log
}

function New-RestorePoint {
    try { Enable-ComputerRestore -Drive ($env:SystemDrive + '\') -ErrorAction Stop } catch { }
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    try { New-ItemProperty -Path $k -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force | Out-Null } catch { }
    Checkpoint-Computer -Description "$AppName - antes de cambios" -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
    Add-ChangeLog 'Deshacer' 'Punto de restauración de Windows creado' 'Info' @{}
}

# ----------------------------------------------------------------------------------------------
#  Firma digital y análisis de riesgo
# ----------------------------------------------------------------------------------------------
function Resolve-CommandPath([string]$Command) {
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $c = $c -replace '^\\\?\?\\', ''
    $c = $c -replace '(?i)^\\systemroot\\', ($env:SystemRoot + '\')
    if ($c -match '(?i)^system32\\') { $c = $env:SystemRoot + '\' + $c }
    $p = $null
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { $p = $c.Substring(1, $end - 1) } else { $p = $c.Trim('"') }
    } else {
        $parts = $c -split ' '
        for ($i = $parts.Count; $i -ge 1; $i--) {
            $cand = ($parts[0..($i - 1)] -join ' ').TrimEnd(',')
            if (Test-FileQuiet $cand) { $p = $cand; break }
            if (Test-FileQuiet ($cand + '.exe')) { $p = $cand + '.exe'; break }
        }
        if (-not $p) { $p = $parts[0].TrimEnd(',') }
    }
    $rooted = $true
    try { $rooted = [IO.Path]::IsPathRooted($p) } catch { $rooted = $true }
    if ($p -and -not $rooted) {
        $sys = $env:SystemRoot + '\System32'
        $gc = Get-Command $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gc) { $p = $gc.Source }
        elseif (Test-FileQuiet ($sys + '\' + $p)) { $p = $sys + '\' + $p }
        elseif (Test-FileQuiet ($sys + '\' + $p + '.exe')) { $p = $sys + '\' + $p + '.exe' }
    }
    return $p
}

function Get-ScriptTargets([string]$Command) {
    $out = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrWhiteSpace($Command)) { return }
    $c = [Environment]::ExpandEnvironmentVariables($Command)
    $ext = 'py|pyw|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|dll|ocx|cpl'
    foreach ($m in [regex]::Matches($c, "(?i)[a-z]:\\[^""<>|*?\r\n,&]*?\.($ext)(?![a-z0-9])")) {
        if (-not $out.Contains($m.Value)) { $out.Add($m.Value) }
    }
    $cd = [regex]::Match($c, '(?i)\bcd\s+(/d\s+)?"?([a-z]:\\[^"&]+?)"?\s*&')
    if ($cd.Success) {
        $dir = $cd.Groups[2].Value.Trim()
        foreach ($m in [regex]::Matches($c, "(?i)(?<![\\:\w.])([\w\-.]+\.($ext))(?![a-z0-9])")) {
            $full = [IO.Path]::Combine($dir, $m.Groups[1].Value)
            if (-not $out.Contains($full)) { $out.Add($full) }
        }
    }
    return $out.ToArray()
}

function Get-FileSignatureInfo([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Estado = 'Sin ruta'; Editor = ''; EsMicrosoft = $false; Existe = $false }
    }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    if (-not (Test-FileQuiet $Path)) {
        $r = [pscustomobject]@{ Estado = 'Archivo no encontrado'; Editor = ''; EsMicrosoft = $false; Existe = $false }
    } else {
        $estado = 'Sin firma'; $editor = ''
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            if ($s.SignerCertificate) {
                $subj = $s.SignerCertificate.Subject
                if ($subj -match 'CN="([^"]+)"') { $editor = $Matches[1] }
                elseif ($subj -match 'CN=([^,]+)') { $editor = $Matches[1].Trim() }
            }
            switch ($s.Status.ToString()) {
                'Valid'        { $estado = 'Firmado' }
                'NotSigned'    { $estado = 'Sin firma' }
                'HashMismatch' { $estado = 'Firma alterada' }
                default        { $estado = 'Firma no válida' }
            }
        } catch { $estado = 'No se pudo comprobar' }
        $isMs = ($estado -eq 'Firmado' -and $editor -match '^Microsoft')
        $r = [pscustomobject]@{ Estado = $estado; Editor = $editor; EsMicrosoft = $isMs; Existe = $true }
    }
    $script:SigCache[$Path] = $r
    return $r
}

function Test-QuickMicrosoft([string]$Path) {
    # Comprobación rápida para archivos dentro de C:\Windows (servicios y drivers del sistema).
    if (-not $Path) { return $false }
    $pl = $Path.ToLowerInvariant()
    $win = $env:SystemRoot.ToLowerInvariant()
    if (-not $pl.StartsWith($win + '\')) { return $false }
    try {
        $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
        return ("$($vi.CompanyName)" -match 'Microsoft')
    } catch { return $false }
}

function Get-RiskAssessment {
    param([string]$Path, [string]$Command, $Sig, [object[]]$Extra = @(), [switch]$IsProcess)
    $m = New-Object 'System.Collections.Generic.List[object]'
    foreach ($x in $Extra) { if ($x) { $m.Add($x) } }
    $p = ("$Path").ToLowerInvariant()
    $c = ("$Command").ToLowerInvariant()
    $leaf = ''
    if ($p) { $leaf = ($p -split '\\')[-1] }
    $win = ("$env:SystemRoot").ToLowerInvariant()
    $inWin        = $p.StartsWith($win + '\')
    $inSysDirs    = $p.StartsWith($win + '\system32\') -or $p.StartsWith($win + '\syswow64\')
    $inDriverDirs = $p.StartsWith($win + '\system32\driverstore\') -or $p.StartsWith($win + '\system32\drivers\')
    $tempLike     = $p -match '\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\perflogs\\|\\\$recycle\.bin\\'
    $dataLike     = $p -match '\\appdata\\|\\programdata\\'

    if (-not $Sig.Existe) {
        if ($p -and -not $IsProcess) { $m.Add(@{ Nivel = 'Resto'; Texto = 'El archivo ya no existe: suele ser un resto de un programa desinstalado.' }) }
    } else {
        if ($Sig.Estado -eq 'Firma alterada') { $m.Add(@{ Nivel = 'Alto'; Texto = 'El archivo se ha modificado después de firmarse.' }) }
        if ($Sig.Estado -ne 'Firmado') {
            if ($tempLike -or $dataLike) { $m.Add(@{ Nivel = 'Alto'; Texto = 'No tiene firma digital y está en una carpeta de datos o temporal (AppData, Temp, ProgramData...). Es lo típico del malware.' }) }
            elseif ($inWin)              { $m.Add(@{ Nivel = 'Alto'; Texto = 'Está dentro de la carpeta de Windows pero no tiene firma de Microsoft.' }) }
            else                         { $m.Add(@{ Nivel = 'Medio'; Texto = 'No tiene firma digital: no se puede comprobar quién lo ha hecho.' }) }
        } else {
            if ($tempLike) { $m.Add(@{ Nivel = 'Medio'; Texto = 'Se ejecuta desde una carpeta temporal, algo poco habitual en un programa legítimo.' }) }
            if ($inWin -and -not $Sig.EsMicrosoft -and -not $inDriverDirs) {
                $m.Add(@{ Nivel = 'Medio'; Texto = "Está dentro de la carpeta de Windows aunque lo firma '$($Sig.Editor)', no Microsoft." })
            }
        }
        if (($script:SystemNames -contains $leaf) -and -not $inSysDirs -and $p -ne ($win + '\explorer.exe')) {
            $m.Add(@{ Nivel = 'Alto'; Texto = "Se llama igual que un archivo de Windows ($leaf) pero no está en su carpeta original. Es un truco habitual del malware." })
        }
    }

    $targets = @(Get-ScriptTargets $Command | Where-Object { -not ($_.ToLowerInvariant().StartsWith($win + '\system32\') -and $_.ToLowerInvariant().EndsWith('.dll')) })
    $isInterp = $script:Interpreters -contains $leaf
    if ($IsProcess -and ($script:QuietInterpretersForProcesses -contains $leaf) -and $targets.Count -eq 0) { $isInterp = $false }
    if ($isInterp) { $m.Add(@{ Nivel = 'Medio'; Texto = "Se ejecuta a través de $leaf, un programa que lanza scripts o comandos. Hay que mirar qué ejecuta." }) }

    foreach ($sp in $script:StrongPatterns) {
        if ($c -match $sp.P) { $m.Add(@{ Nivel = $sp.N; Texto = $sp.T }) }
    }
    foreach ($t in $targets) {
        $tl = $t.ToLowerInvariant()
        if ($tl -match '\\appdata\\|\\programdata\\|\\temp\\|\\users\\public\\' -or $tl.StartsWith($win + '\')) {
            $m.Add(@{ Nivel = 'Alto'; Texto = "Ejecuta '$t', guardado en una carpeta poco habitual para eso." })
        } else {
            $m.Add(@{ Nivel = 'Medio'; Texto = "Ejecuta el archivo '$t'." })
        }
    }

    $nivel = 'Normal'
    foreach ($x in $m) { if ($x.Nivel -eq 'Resto' -and $nivel -eq 'Normal') { $nivel = 'Resto' } }
    foreach ($x in $m) { if ($x.Nivel -eq 'Medio' -and $nivel -ne 'Sospechoso') { $nivel = 'Revisar' } }
    foreach ($x in $m) { if ($x.Nivel -eq 'Alto') { $nivel = 'Sospechoso' } }
    $textos = @()
    foreach ($x in $m) { if ($textos -notcontains $x.Texto) { $textos += $x.Texto } }
    return [pscustomobject]@{ Nivel = $nivel; Motivos = $textos }
}

function Get-RiskOrder([string]$Riesgo) {
    switch ($Riesgo) { 'Sospechoso' { 0 } 'Revisar' { 1 } 'Resto' { 2 } default { 3 } }
}

# ----------------------------------------------------------------------------------------------
#  Módulo: Inicio automático
# ----------------------------------------------------------------------------------------------
function New-AutoEntry {
    param($Tipo, $Nombre, $Comando, $Ruta, $Origen, $Estado, $Data, [string[]]$Acciones, [object[]]$ExtraMotivos = @(), [switch]$SkipIfMicrosoftNormal)
    $sig  = Get-FileSignatureInfo $Ruta
    $risk = Get-RiskAssessment -Path $Ruta -Command $Comando -Sig $sig -Extra $ExtraMotivos
    if ($SkipIfMicrosoftNormal -and $sig.EsMicrosoft -and $risk.Nivel -eq 'Normal') { return }
    $id = Get-ShortHash "$Tipo|$Nombre|$Comando"
    return [pscustomobject]@{
        Id = $id; Tipo = $Tipo; Nombre = "$Nombre"; Comando = "$Comando"; Ruta = "$Ruta"; Origen = $Origen
        Estado = $Estado; Firma = $sig.Estado; Editor = $sig.Editor; EsMicrosoft = $sig.EsMicrosoft; Existe = $sig.Existe
        Riesgo = $risk.Nivel; Motivos = $risk.Motivos; Data = $Data; Acciones = $Acciones
    }
}

function Get-ApprovedBytes([string]$Key, [string]$Name) {
    if (-not $Key -or -not (Test-Path -LiteralPath $Key)) { return $null }
    try { return [byte[]]((Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction Stop).$Name) } catch { return $null }
}

function ConvertTo-StartText($Start) {
    switch ("$Start") { '0' { 'al arrancar (boot)' } '1' { 'sistema' } '2' { 'automático' } '3' { 'manual' } '4' { 'desactivado' } default { 'desconocido' } }
}

function Get-RunKeyEntries {
    $defs = @(
        @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';              Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run';   Origen = 'Registro · usuario actual · Run' },
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';              Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run';   Origen = 'Registro · todos los usuarios · Run' },
        @{ Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';  Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; Origen = 'Registro · todos los usuarios · Run (32 bits)' },
        @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce';          Approved = $null; Origen = 'Registro · usuario actual · RunOnce (se ejecuta una sola vez)' },
        @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';          Approved = $null; Origen = 'Registro · todos los usuarios · RunOnce (se ejecuta una sola vez)' }
    )
    foreach ($d in $defs) {
        if (-not (Test-Path -LiteralPath $d.Key)) { continue }
        $k = Get-Item -LiteralPath $d.Key
        foreach ($n in $k.GetValueNames()) {
            if ([string]::IsNullOrEmpty($n)) { continue }
            $cmd = [string]$k.GetValue($n, '', 'DoNotExpandEnvironmentNames')
            $estado = 'Activo'
            $acciones = @('Eliminar')
            if ($d.Approved) {
                $acciones = @('Desactivar', 'Eliminar')
                $ab = Get-ApprovedBytes $d.Approved $n
                if ($ab -and $ab.Length -gt 0 -and ($ab[0] % 2) -eq 1) { $estado = 'Desactivado' }
            }
            New-AutoEntry -Tipo 'Registro (Run)' -Nombre $n -Comando $cmd -Ruta (Resolve-CommandPath $cmd) -Origen $d.Origen -Estado $estado `
                -Data @{ Kind = 'Run'; Key = $d.Key; ValueName = $n; Approved = $d.Approved } -Acciones $acciones
        }
    }
}

function Get-StartupFolderEntries {
    $defs = @(
        @{ Dir = [Environment]::GetFolderPath('Startup');       Approved = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Origen = 'Carpeta Inicio · usuario actual' },
        @{ Dir = [Environment]::GetFolderPath('CommonStartup'); Approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; Origen = 'Carpeta Inicio · todos los usuarios' }
    )
    $sh = $null
    try { $sh = New-Object -ComObject WScript.Shell } catch { }
    foreach ($d in $defs) {
        if (-not $d.Dir -or -not (Test-Path -LiteralPath $d.Dir)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $d.Dir -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -ieq 'desktop.ini') { continue }
            $cmd = $f.FullName; $path = $f.FullName
            if ($f.Extension -ieq '.lnk' -and $sh) {
                try {
                    $lnk = $sh.CreateShortcut($f.FullName)
                    if ($lnk.TargetPath) { $path = $lnk.TargetPath; $cmd = ('"' + $lnk.TargetPath + '" ' + $lnk.Arguments).Trim() }
                } catch { }
            }
            $estado = 'Activo'
            $ab = Get-ApprovedBytes $d.Approved $f.Name
            if ($ab -and $ab.Length -gt 0 -and ($ab[0] % 2) -eq 1) { $estado = 'Desactivado' }
            New-AutoEntry -Tipo 'Carpeta Inicio' -Nombre $f.Name -Comando $cmd -Ruta $path -Origen ($d.Origen + ' (' + $f.FullName + ')') -Estado $estado `
                -Data @{ Kind = 'Startup'; File = $f.FullName; Approved = $d.Approved; ValueName = $f.Name } -Acciones @('Desactivar', 'Eliminar')
        }
    }
}

function Get-TaskEntries {
    $win = $env:SystemRoot.ToLowerInvariant()
    $msSig = [pscustomobject]@{ Estado = 'Firmado'; Editor = 'Microsoft'; EsMicrosoft = $true; Existe = $true }
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $execs = @($t.Actions | Where-Object { $_.Execute })
        if ($execs.Count -eq 0) { continue }
        $cmds = @(); $first = $null
        foreach ($a in $execs) {
            $exe = [Environment]::ExpandEnvironmentVariables(([string]$a.Execute).Trim().Trim('"'))
            $resolved = $exe
            $rooted = $true
            try { $rooted = [IO.Path]::IsPathRooted($exe) } catch { }
            if (-not $rooted) {
                $gc = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($gc) { $resolved = $gc.Source }
                elseif ($a.WorkingDirectory) { $resolved = Join-Path ([Environment]::ExpandEnvironmentVariables($a.WorkingDirectory)) $exe }
            }
            if (-not $first) { $first = $resolved }
            $cmds += ('"' + $resolved + '" ' + $a.Arguments).Trim()
        }
        $cmd = $cmds -join '   ;   '
        $isMsFolder = $t.TaskPath -like '\Microsoft\*'
        if ($isMsFolder) {
            # Tareas de la carpeta de Microsoft: solo se muestran si algo no cuadra.
            $fl = "$first".ToLowerInvariant()
            $sysExe = $fl.StartsWith($win + '\') -or $fl -like '*\program files*\windows*' -or $fl -like '*\program files*\microsoft*'
            $pre = Get-RiskAssessment -Path $first -Command $cmd -Sig $msSig
            if ($sysExe -and $pre.Nivel -ne 'Sospechoso') { continue }
        }
        $extra = @()
        if ($t.Settings -and $t.Settings.Hidden) { $extra += @{ Nivel = 'Medio'; Texto = 'La tarea está marcada como oculta, para que no se vea fácilmente.' } }
        $estado = 'Activo'
        if ("$($t.State)" -eq 'Disabled') { $estado = 'Desactivado' }
        $user = ''
        if ($t.Principal) { $user = $t.Principal.UserId }
        if (-not $user) { $user = 'usuario que inicia sesión' }
        New-AutoEntry -Tipo 'Tarea programada' -Nombre ($t.TaskPath + $t.TaskName) -Comando $cmd -Ruta $first `
            -Origen ('Programador de tareas · se ejecuta como: ' + $user) -Estado $estado `
            -Data @{ Kind = 'Task'; TaskName = $t.TaskName; TaskPath = $t.TaskPath } -Acciones @('Desactivar', 'Eliminar') -ExtraMotivos $extra
    }
}

function Get-ServicePathInfo($Name, $PathName) {
    $path = Resolve-CommandPath $PathName
    if ($path -and $path.ToLowerInvariant().EndsWith('\svchost.exe')) {
        $dll = (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $Name + '\Parameters') -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
        if ($dll) { $path = [Environment]::ExpandEnvironmentVariables($dll) }
    }
    return $path
}

function Get-ServiceEntries {
    foreach ($s in (Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
        $path = Get-ServicePathInfo $s.Name $s.PathName
        if (Test-QuickMicrosoft $path) { continue }
        $start = (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $s.Name) -Name Start -ErrorAction SilentlyContinue).Start
        $estado = 'Activo'
        if ($start -eq 4) { $estado = 'Desactivado' } elseif ($s.State -eq 'Running') { $estado = 'Activo (en marcha)' }
        New-AutoEntry -Tipo 'Servicio' -Nombre ("$($s.DisplayName) [$($s.Name)]") -Comando $s.PathName -Ruta $path `
            -Origen ('Servicio de Windows · inicio: ' + (ConvertTo-StartText $start) + ' · cuenta: ' + $s.StartName) -Estado $estado `
            -Data @{ Kind = 'Service'; ServiceName = $s.Name } -Acciones @('Desactivar', 'Eliminar') -SkipIfMicrosoftNormal
    }
}

function Get-DriverEntries {
    foreach ($d in (Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue)) {
        $path = Resolve-CommandPath $d.PathName
        if (Test-QuickMicrosoft $path) { continue }
        $start = (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $d.Name) -Name Start -ErrorAction SilentlyContinue).Start
        $estado = 'Activo'
        if ($start -eq 4) { $estado = 'Desactivado' } elseif ($d.State -eq 'Running') { $estado = 'Activo (en marcha)' }
        New-AutoEntry -Tipo 'Driver' -Nombre ("$($d.DisplayName) [$($d.Name)]") -Comando $d.PathName -Ruta $path `
            -Origen ('Controlador (driver) · inicio: ' + (ConvertTo-StartText $start)) -Estado $estado `
            -Data @{ Kind = 'Driver'; ServiceName = $d.Name } -Acciones @('Desactivar') -SkipIfMicrosoftNormal
    }
}

function Get-WmiEntries {
    foreach ($cls in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
        foreach ($w in (Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction SilentlyContinue)) {
            if ($cls -eq 'CommandLineEventConsumer') {
                $cmd = "$($w.CommandLineTemplate)"
                if (-not $cmd) { $cmd = "$($w.ExecutablePath)" }
                $path = Resolve-CommandPath $cmd
            } else {
                $cmd = "[$($w.ScriptingEngine)] $($w.ScriptText)"
                $path = $null
            }
            New-AutoEntry -Tipo 'WMI' -Nombre $w.Name -Comando $cmd -Ruta $path -Origen ('Suscripción WMI (' + $cls + ')') -Estado 'Activo' `
                -Data @{ Kind = 'Wmi'; Name = $w.Name; Class = $cls } -Acciones @('Eliminar') `
                -ExtraMotivos @(@{ Nivel = 'Medio'; Texto = 'Usa una suscripción WMI para ejecutarse. Casi ningún programa doméstico lo hace; es una técnica de malware avanzado.' })
        }
    }
}

function Get-AutostartEntries([scriptblock]$Progress) {
    $all = @()
    & $Progress 'Leyendo el registro (Run)...'
    $all += @(Get-RunKeyEntries)
    & $Progress 'Leyendo la carpeta Inicio...'
    $all += @(Get-StartupFolderEntries)
    & $Progress 'Leyendo las tareas programadas (puede tardar un poco)...'
    $all += @(Get-TaskEntries)
    & $Progress 'Leyendo los servicios...'
    $all += @(Get-ServiceEntries)
    & $Progress 'Leyendo los drivers...'
    $all += @(Get-DriverEntries)
    & $Progress 'Buscando suscripciones WMI...'
    $all += @(Get-WmiEntries)
    return @($all | Where-Object { $_ })
}

function Set-ApprovedState([string]$ApprovedKey, [string]$Name, [bool]$Enable, [string]$Descripcion) {
    if ($Enable) { $bytes = [byte[]](2,0,0,0,0,0,0,0,0,0,0,0) }
    else         { $bytes = [byte[]](@(3,0,0,0) + [BitConverter]::GetBytes([DateTime]::Now.ToFileTime())) }
    Set-RegValueLogged 'Inicio automático' $Descripcion $ApprovedKey $Name $bytes 'Binary'
}

function Invoke-AutoAction($Entry, [string]$Action) {
    $d = $Entry.Data
    $name = $Entry.Nombre
    switch ($d.Kind) {
        'Run' {
            if ($Action -eq 'Eliminar') { Remove-RegValueLogged 'Inicio automático' "Eliminado del inicio (registro): $name" $d.Key $d.ValueName }
            else { Set-ApprovedState $d.Approved $d.ValueName ($Action -eq 'Activar') ("$Action (registro): $name") }
        }
        'Startup' {
            if ($Action -eq 'Eliminar') {
                $dest = Join-Path $script:BackupDir ('Inicio-' + (Get-Timestamp))
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                $copia = Join-Path $dest ([IO.Path]::GetFileName($d.File))
                Move-Item -LiteralPath $d.File -Destination $copia -Force -ErrorAction Stop
                Add-ChangeLog 'Inicio automático' "Eliminado de la carpeta Inicio: $name" 'Archivo' @{ Origen = $d.File; Copia = $copia }
            } else { Set-ApprovedState $d.Approved $d.ValueName ($Action -eq 'Activar') ("$Action (carpeta Inicio): $name") }
        }
        'Task' {
            if ($Action -eq 'Eliminar') {
                $xml = Export-ScheduledTask -TaskName $d.TaskName -TaskPath $d.TaskPath -ErrorAction Stop
                $file = Join-Path $script:BackupDir ('Tarea-' + (Get-Timestamp) + '-' + ($d.TaskName -replace '[^\w\-]', '_') + '.xml')
                [IO.File]::WriteAllText($file, $xml, [Text.Encoding]::Unicode)
                Unregister-ScheduledTask -TaskName $d.TaskName -TaskPath $d.TaskPath -Confirm:$false -ErrorAction Stop
                Add-ChangeLog 'Inicio automático' "Tarea programada eliminada: $name" 'TareaEliminada' @{ TaskName = $d.TaskName; TaskPath = $d.TaskPath; Xml = $file }
            } elseif ($Action -eq 'Desactivar') {
                Disable-ScheduledTask -TaskName $d.TaskName -TaskPath $d.TaskPath -ErrorAction Stop | Out-Null
                Add-ChangeLog 'Inicio automático' "Tarea programada desactivada: $name" 'TareaEstado' @{ TaskName = $d.TaskName; TaskPath = $d.TaskPath; EstabaActiva = $true }
            } else {
                Enable-ScheduledTask -TaskName $d.TaskName -TaskPath $d.TaskPath -ErrorAction Stop | Out-Null
                Add-ChangeLog 'Inicio automático' "Tarea programada reactivada: $name" 'TareaEstado' @{ TaskName = $d.TaskName; TaskPath = $d.TaskPath; EstabaActiva = $false }
            }
        }
        { $_ -eq 'Service' -or $_ -eq 'Driver' } {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $d.ServiceName
            if ($Action -eq 'Eliminar') {
                $file = Join-Path $script:BackupDir ('Servicio-' + (Get-Timestamp) + '-' + ($d.ServiceName -replace '[^\w\-]', '_') + '.reg')
                & reg.exe export ('HKLM\SYSTEM\CurrentControlSet\Services\' + $d.ServiceName) $file /y 2>&1 | Out-Null
                Stop-Service -Name $d.ServiceName -Force -ErrorAction SilentlyContinue
                $out = & sc.exe delete $d.ServiceName 2>&1
                if ($LASTEXITCODE -ne 0) { throw "No se pudo eliminar el servicio: $out" }
                Add-ChangeLog 'Inicio automático' "Servicio eliminado: $name (se restaura del todo al reiniciar)" 'ServicioEliminado' @{ Name = $d.ServiceName; RegFile = $file }
            } elseif ($Action -eq 'Desactivar') {
                Set-RegValueLogged 'Inicio automático' "Desactivado ($($Entry.Tipo)): $name" $key 'Start' 4 'DWord'
                if ($d.Kind -eq 'Service') { Stop-Service -Name $d.ServiceName -Force -ErrorAction SilentlyContinue }
            } else {
                Set-RegValueLogged 'Inicio automático' "Reactivado en modo manual ($($Entry.Tipo)): $name" $key 'Start' 3 'DWord'
            }
        }
        'Wmi' {
            $file = Join-Path $script:BackupDir ('WMI-' + (Get-Timestamp) + '.txt')
            $consumer = Get-CimInstance -Namespace 'root/subscription' -ClassName $d.Class -ErrorAction Stop | Where-Object { $_.Name -eq $d.Name }
            ($consumer | Format-List * | Out-String) | Set-Content -LiteralPath $file -Encoding UTF8
            Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue |
                Where-Object { $_.Consumer -and $_.Consumer.Name -eq $d.Name } | Remove-CimInstance -ErrorAction SilentlyContinue
            $consumer | Remove-CimInstance -ErrorAction Stop
            Add-ChangeLog 'Inicio automático' "Suscripción WMI eliminada: $name (copia en texto: $file)" 'NoReversible' @{ Copia = $file }
        }
    }
}

# ----------------------------------------------------------------------------------------------
#  Módulo: Procesos
# ----------------------------------------------------------------------------------------------
function Get-ProcessScan([int]$Seconds = 5) {
    $t0 = @{}
    foreach ($p in (Get-Process)) { try { $t0[$p.Id] = $p.TotalProcessorTime.TotalMilliseconds } catch { } }
    Start-Sleep -Seconds $Seconds
    $cpuCount = [Environment]::ProcessorCount
    $cim = @{}
    foreach ($w in (Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) { $cim[[int]$w.ProcessId] = $w }
    $list = @()
    foreach ($p in (Get-Process)) {
        if ($p.Id -le 4 -or $p.Id -eq $PID) { continue }
        $cpu = 0.0
        try { if ($t0.ContainsKey($p.Id)) { $cpu = [math]::Round(($p.TotalProcessorTime.TotalMilliseconds - $t0[$p.Id]) / ($Seconds * 1000) / $cpuCount * 100, 1) } } catch { }
        $path = $null; $cmd = ''
        if ($cim.ContainsKey($p.Id)) { $path = $cim[$p.Id].ExecutablePath; $cmd = "$($cim[$p.Id].CommandLine)" }
        if (-not $path) { try { $path = $p.Path } catch { } }
        if ($path) {
            if (Test-QuickMicrosoft $path) { $sig = [pscustomobject]@{ Estado = 'Firmado'; Editor = 'Microsoft'; EsMicrosoft = $true; Existe = $true } }
            else { $sig = Get-FileSignatureInfo $path }
            $risk = Get-RiskAssessment -Path $path -Command $cmd -Sig $sig -IsProcess
        } else {
            $sig  = [pscustomobject]@{ Estado = 'Protegido por Windows'; Editor = ''; EsMicrosoft = $false; Existe = $false }
            $risk = [pscustomobject]@{ Nivel = 'Normal'; Motivos = @() }
        }
        $ram = 0
        try { $ram = [math]::Round($p.WorkingSet64 / 1MB) } catch { }
        $list += [pscustomobject]@{
            Id = [string]$p.Id; Proceso = $p.ProcessName; ProcId = $p.Id; CPU = $cpu; RAM = $ram
            Firma = $sig.Estado; Editor = $sig.Editor; Ruta = "$path"; Comando = $cmd; Existe = $sig.Existe
            Riesgo = $risk.Nivel; Motivos = $risk.Motivos
        }
    }
    return $list
}

# ----------------------------------------------------------------------------------------------
#  Módulo: Seguridad
# ----------------------------------------------------------------------------------------------
function New-Check($Id, $Nombre, $Estado, $Detalle, $Explicacion, $AccionTexto = '', $Datos = $null) {
    return [pscustomobject]@{ Id = $Id; Nombre = $Nombre; Estado = $Estado; Detalle = $Detalle; Explicacion = $Explicacion; AccionTexto = $AccionTexto; Datos = $Datos }
}

function Get-SecurityChecks {
    $list = @()
    $mp = $null;   try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
    $pref = $null; try { $pref = Get-MpPreference -ErrorAction Stop } catch { }
    $avs = @()
    try { $avs = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch { }
    $others = @($avs | Where-Object { $_ -and $_ -notmatch 'Defender' })

    # 1. Antivirus
    $exp = 'El antivirus vigila en tiempo real lo que se descarga y ejecuta. Windows trae Microsoft Defender, que es suficiente para un uso doméstico. Si instalas otro antivirus, Defender se apaga solo para no chocar con él.'
    if ($mp -and $mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {
        $list += New-Check 'av' 'Antivirus' 'Correcto' 'Microsoft Defender está activo, con protección en tiempo real.' $exp 'Abrir Seguridad de Windows'
    } elseif ($others.Count -gt 0) {
        $list += New-Check 'av' 'Antivirus' 'Info' ('El antivirus activo es: ' + ($others -join ', ') + '. Defender está en pausa porque hay otro antivirus.') ($exp + ' Si ya no quieres ese antivirus, desinstálalo y Defender volverá a activarse solo.') 'Abrir Seguridad de Windows'
    } else {
        $list += New-Check 'av' 'Antivirus' 'Problema' 'No hay ningún antivirus activo con protección en tiempo real.' ($exp + ' Algunos malware lo apagan para que no los detecte. Revisa también la comprobación de "Bloqueos del sistema".') 'Abrir Seguridad de Windows'
    }

    # 2. Exclusiones
    $items = @()
    if ($pref) {
        foreach ($v in @($pref.ExclusionPath))      { if ($v -and $v -notlike 'N/A*') { $items += [pscustomobject]@{ Clase = 'Path';      Valor = $v; Texto = "Carpeta o archivo: $v" } } }
        foreach ($v in @($pref.ExclusionProcess))   { if ($v -and $v -notlike 'N/A*') { $items += [pscustomobject]@{ Clase = 'Process';   Valor = $v; Texto = "Programa: $v" } } }
        foreach ($v in @($pref.ExclusionExtension)) { if ($v -and $v -notlike 'N/A*') { $items += [pscustomobject]@{ Clase = 'Extension'; Valor = $v; Texto = "Tipo de archivo: $v" } } }
    }
    $exp = 'Una exclusión es algo que el antivirus tiene prohibido revisar. Se usan a veces para que un juego cargue más rápido, pero el malware las añade para que el antivirus no lo vea. En este PC, el minero excluyó toda la carpeta C:\Windows.'
    if ($items.Count -eq 0) {
        $list += New-Check 'excl' 'Exclusiones del antivirus' 'Correcto' 'No hay ninguna exclusión.' $exp
    } else {
        $broad = @($items | Where-Object { $_.Valor -match '^(?i)[a-z]:\\?$|^(?i)[a-z]:\\windows\\?$|^(?i)[a-z]:\\users\\?$|(?i)\\temp\\?$|^(?i)\.?(exe|dll|ps1|bat|cmd|vbs|js|scr)$|(?i)xmrig|(?i)\\appdata\\?$|(?i)\\programdata\\?$' })
        $estado = 'Atención'
        if ($broad.Count -gt 0) { $estado = 'Problema' }
        $list += New-Check 'excl' 'Exclusiones del antivirus' $estado ("Hay $($items.Count) exclusión(es): " + (($items | ForEach-Object { $_.Texto }) -join ' | ')) ($exp + ' Si no las has puesto tú a propósito, quítalas.') 'Revisar y quitar exclusiones' $items
    }

    # 3. Bloqueos del sistema (políticas)
    $polDefs = @(
        @{ K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';                         N = 'DisableAntiSpyware';         T = 'Defender desactivado por política' },
        @{ K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';                         N = 'DisableAntiVirus';           T = 'Antivirus desactivado por política' },
        @{ K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';    N = 'DisableRealtimeMonitoring';  T = 'Protección en tiempo real desactivada por política' },
        @{ K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';    N = 'DisableBehaviorMonitoring';  T = 'Vigilancia de comportamiento desactivada por política' },
        @{ K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';    N = 'DisableOnAccessProtection';  T = 'Análisis al abrir archivos desactivado por política' },
        @{ K = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection';    N = 'DisableIOAVProtection';      T = 'Análisis de descargas desactivado por política' },
        @{ K = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System';            N = 'DisableTaskMgr';             T = 'Administrador de tareas bloqueado (usuario)' },
        @{ K = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';            N = 'DisableTaskMgr';             T = 'Administrador de tareas bloqueado (equipo)' },
        @{ K = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System';            N = 'DisableRegistryTools';       T = 'Editor del registro bloqueado' },
        @{ K = 'HKCU:\Software\Policies\Microsoft\Windows\System';                           N = 'DisableCMD';                 T = 'Símbolo del sistema bloqueado' }
    )
    $found = @()
    foreach ($p in $polDefs) {
        $v = $null
        try { $v = (Get-ItemProperty -LiteralPath $p.K -Name $p.N -ErrorAction Stop).($p.N) } catch { }
        if ($null -ne $v -and "$v" -ne '0') { $found += [pscustomobject]@{ Key = $p.K; Name = $p.N; Texto = $p.T } }
    }
    $ifeoKeys = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')
    foreach ($ik in $ifeoKeys) {
        foreach ($sk in (Get-ChildItem -LiteralPath $ik -ErrorAction SilentlyContinue)) {
            $dbg = $sk.GetValue('Debugger')
            if ($dbg) { $found += [pscustomobject]@{ Key = $sk.PSPath; Name = 'Debugger'; Texto = "Al abrir $($sk.PSChildName) se ejecuta en su lugar: $dbg" } }
        }
    }
    $exp = 'Son ajustes que impiden usar herramientas de Windows (antivirus, Administrador de tareas, editor del registro...) o que cambian un programa por otro al abrirlo. El malware los usa para que no puedas detectarlo ni quitarlo. Excepción: si instalaste Process Explorer como sustituto del Administrador de tareas, aparecerá aquí y es normal.'
    if ($found.Count -eq 0) {
        $list += New-Check 'pol' 'Bloqueos del sistema' 'Correcto' 'No hay bloqueos ni programas sustituidos.' $exp
    } else {
        $list += New-Check 'pol' 'Bloqueos del sistema' 'Problema' (($found | ForEach-Object { $_.Texto }) -join ' | ') $exp 'Quitar estos bloqueos' $found
    }

    # 4. Winlogon (lo que se carga al iniciar sesión)
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = $null; $userinit = $null
    try { $wlp = Get-ItemProperty -LiteralPath $wl -ErrorAction Stop; $shell = "$($wlp.Shell)"; $userinit = "$($wlp.Userinit)" } catch { }
    $exp = 'Al iniciar sesión, Windows abre el escritorio (explorer.exe) y el programa userinit.exe. Algunos malware añaden aquí su propio programa para arrancar antes que nada.'
    $okShell = ($shell -match '^\s*explorer\.exe\s*$')
    $okUserinit = ($userinit -match '^(?i)\s*[a-z]:\\windows\\system32\\userinit\.exe\s*,?\s*$')
    if ($okShell -and $okUserinit) {
        $list += New-Check 'winlogon' 'Inicio de sesión (Winlogon)' 'Correcto' 'Los valores son los originales de Windows.' $exp
    } else {
        $list += New-Check 'winlogon' 'Inicio de sesión (Winlogon)' 'Problema' "Shell = '$shell' · Userinit = '$userinit'" ($exp + ' Los valores correctos son "explorer.exe" y "C:\Windows\system32\userinit.exe,".') 'Restaurar los valores de Windows'
    }

    # 5. Firmas del antivirus
    $exp = 'Las firmas son la lista de amenazas conocidas que usa el antivirus. Se actualizan solas varias veces al día; si llevan días sin actualizarse, el antivirus no reconoce el malware nuevo.'
    if ($mp) {
        $age = $mp.AntivirusSignatureAge
        if ($age -le 2) { $list += New-Check 'firmas' 'Firmas del antivirus' 'Correcto' "Actualizadas (hace $age día(s))." $exp 'Actualizar ahora' }
        else { $list += New-Check 'firmas' 'Firmas del antivirus' 'Atención' "Llevan $age días sin actualizarse." $exp 'Actualizar ahora' }

        # 6. Análisis
        $exp = 'Un análisis revisa los archivos del disco en busca de amenazas. El rápido tarda unos minutos y revisa las zonas donde suele esconderse el malware.'
        $q = $mp.QuickScanAge; $f = $mp.FullScanAge
        $qt = 'nunca'; if ($q -lt 10000) { $qt = "hace $q día(s)" }
        $ft = 'nunca'; if ($f -lt 10000) { $ft = "hace $f día(s)" }
        $st = 'Correcto'; if ($q -gt 14 -and $f -gt 14) { $st = 'Atención' }
        $list += New-Check 'scan' 'Análisis del antivirus' $st "Último análisis rápido: $qt · último análisis completo: $ft." $exp 'Lanzar análisis rápido'

        # 7. Protección contra alteraciones
        $exp = 'Impide que otros programas (incluido el malware) cambien la configuración de Defender. Debería estar activada.'
        if ($mp.IsTamperProtected) { $list += New-Check 'tamper' 'Protección contra alteraciones' 'Correcto' 'Activada.' $exp }
        else { $list += New-Check 'tamper' 'Protección contra alteraciones' 'Atención' 'Desactivada.' ($exp + ' Se activa a mano en Seguridad de Windows > Protección antivirus > Administrar la configuración.') 'Abrir ese ajuste' }
    }

    # 8. Control de cuentas (UAC)
    $lua = $null
    try { $lua = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA } catch { }
    $exp = 'El Control de cuentas de usuario es la ventana que pregunta "¿Quieres permitir que esta aplicación haga cambios?". Evita que un programa obtenga permisos de administrador sin que lo sepas.'
    if ($lua -eq 0) { $list += New-Check 'uac' 'Control de cuentas (UAC)' 'Problema' 'Está desactivado.' $exp 'Activarlo (requiere reiniciar)' }
    else { $list += New-Check 'uac' 'Control de cuentas (UAC)' 'Correcto' 'Activado.' $exp }

    # 9. Firewall
    $exp = 'El firewall bloquea conexiones no deseadas desde internet. Debe estar activado en todos los perfiles (dominio, privado y público).'
    try {
        $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object { $_.Name })
        if ($off.Count -eq 0) { $list += New-Check 'fw' 'Firewall de Windows' 'Correcto' 'Activado en todos los perfiles.' $exp }
        else { $list += New-Check 'fw' 'Firewall de Windows' 'Problema' ('Desactivado en: ' + ($off -join ', ')) $exp 'Activarlo' $off }
    } catch { }

    # 10. Archivo hosts
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $exp = 'El archivo hosts decide a qué servidor va cada dirección web antes de preguntar a internet. El malware lo cambia para bloquear webs de antivirus o mandarte a páginas falsas.'
    try {
        $lines = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$' })
        if ($lines.Count -eq 0) { $list += New-Check 'hosts' 'Archivo hosts' 'Correcto' 'Sin modificaciones.' $exp }
        else { $list += New-Check 'hosts' 'Archivo hosts' 'Atención' ("Tiene $($lines.Count) línea(s) añadida(s): " + (($lines | Select-Object -First 5) -join ' | ')) ($exp + ' Algunos programas legítimos lo usan (por ejemplo, para bloquear publicidad). Si no lo reconoces, revísalo.') 'Abrir el archivo' }
    } catch { }

    # 11. Proxy
    $is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $exp = 'Un proxy hace que tu conexión a internet pase por otro ordenador. En casa no suele hacer falta; el malware lo configura para espiar o redirigir tu navegación.'
    try {
        $ip = Get-ItemProperty -LiteralPath $is -ErrorAction Stop
        $pe = ($ip.ProxyEnable -eq 1)
        $pac = "$($ip.AutoConfigURL)"
        if (-not $pe -and -not $pac) { $list += New-Check 'proxy' 'Proxy de internet' 'Correcto' 'No hay proxy configurado.' $exp }
        else {
            $det = @(); if ($pe) { $det += "Proxy: $($ip.ProxyServer)" }; if ($pac) { $det += "Script de configuración: $pac" }
            $list += New-Check 'proxy' 'Proxy de internet' 'Atención' ($det -join ' | ') $exp 'Desactivar el proxy'
        }
    } catch { }

    # 12. Secure Boot
    $exp = 'El arranque seguro impide que se cargue software no autorizado antes que Windows. Lo exigen varios juegos con antitrampas (Battlefield 6, Call of Duty, Valorant en Windows 11). Se activa en la BIOS.'
    $sb = $null; try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = $null }
    if ($sb -eq $true) { $list += New-Check 'sb' 'Arranque seguro (Secure Boot)' 'Correcto' 'Activado.' $exp }
    elseif ($sb -eq $false) { $list += New-Check 'sb' 'Arranque seguro (Secure Boot)' 'Atención' 'El PC arranca en modo UEFI, pero el arranque seguro está desactivado.' $exp 'Cómo activarlo' }
    else { $list += New-Check 'sb' 'Arranque seguro (Secure Boot)' 'Atención' 'El PC arranca en modo antiguo (BIOS/CSM) o no se pudo comprobar.' $exp 'Cómo activarlo' }

    # 13. TPM
    $exp = 'El TPM es un chip de seguridad (en los Ryzen va dentro del procesador y se llama fTPM). Lo necesitan Windows 11 y algunos antitrampas. Se activa en la BIOS.'
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmPresent -and $tpm.TpmReady) { $list += New-Check 'tpm' 'Chip de seguridad (TPM)' 'Correcto' 'Presente y listo.' $exp }
        else { $list += New-Check 'tpm' 'Chip de seguridad (TPM)' 'Atención' 'No está activado o no está listo.' $exp 'Cómo activarlo' }
    } catch { $list += New-Check 'tpm' 'Chip de seguridad (TPM)' 'Atención' 'No se pudo comprobar.' $exp 'Cómo activarlo' }

    return $list
}

function Get-StateOrder([string]$Estado) {
    switch ($Estado) { 'Problema' { 0 } 'Atención' { 1 } 'Info' { 2 } default { 3 } }
}

# ----------------------------------------------------------------------------------------------
#  Interfaz gráfica
# ----------------------------------------------------------------------------------------------
$script:Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="RigWarden" Height="800" Width="1220" MinHeight="620" MinWidth="980"
        WindowStartupLocation="CenterScreen" Background="#F4F6F9" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="0,0,8,8"/>
      <Setter Property="Background" Value="#FFFFFF"/>
      <Setter Property="BorderBrush" Value="#B8C4D0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="ToolTipService.ShowOnDisabled" Value="True"/>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#1F4E79"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderBrush" Value="#1F4E79"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Foreground" Value="#A4262C"/>
      <Setter Property="BorderBrush" Value="#D9A0A3"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#E3E8ED"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="BorderBrush" Value="#C9D3DD"/>
      <Setter Property="RowHeaderWidth" Value="0"/>
    </Style>
    <Style x:Key="RiskRow" TargetType="DataGridRow">
      <Style.Triggers>
        <DataTrigger Binding="{Binding Riesgo}" Value="Sospechoso"><Setter Property="Background" Value="#FFE3E3"/></DataTrigger>
        <DataTrigger Binding="{Binding Riesgo}" Value="Revisar"><Setter Property="Background" Value="#FFF4D6"/></DataTrigger>
        <DataTrigger Binding="{Binding Riesgo}" Value="Resto"><Setter Property="Background" Value="#EFEFEF"/></DataTrigger>
        <DataTrigger Binding="{Binding Estado}" Value="Desactivado"><Setter Property="Foreground" Value="#888888"/></DataTrigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="StateRow" TargetType="DataGridRow">
      <Style.Triggers>
        <DataTrigger Binding="{Binding Estado}" Value="Problema"><Setter Property="Background" Value="#FFE3E3"/></DataTrigger>
        <DataTrigger Binding="{Binding Estado}" Value="Atención"><Setter Property="Background" Value="#FFF4D6"/></DataTrigger>
        <DataTrigger Binding="{Binding Estado}" Value="Correcto"><Setter Property="Background" Value="#E8F5EC"/></DataTrigger>
        <DataTrigger Binding="{Binding Estado}" Value="Info"><Setter Property="Background" Value="#EAF1FB"/></DataTrigger>
        <DataTrigger Binding="{Binding Estado}" Value="Deshecho"><Setter Property="Foreground" Value="#888888"/></DataTrigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Detail" TargetType="Border">
      <Setter Property="Background" Value="White"/>
      <Setter Property="BorderBrush" Value="#C9D3DD"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12"/>
      <Setter Property="Margin" Value="0,10,0,0"/>
    </Style>
    <Style x:Key="Intro" TargetType="TextBlock">
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="0,0,0,10"/>
      <Setter Property="Foreground" Value="#333333"/>
    </Style>
  </Window.Resources>

  <DockPanel>
    <Border DockPanel.Dock="Top" Background="#1F4E79" Padding="18,12">
      <StackPanel>
        <TextBlock x:Name="TxtTitle" Foreground="White" FontSize="20" FontWeight="SemiBold"/>
        <TextBlock x:Name="TxtSubtitle" Foreground="#D6E4F0"/>
      </StackPanel>
    </Border>
    <Border DockPanel.Dock="Bottom" Background="#E9EEF3" Padding="12,6">
      <TextBlock x:Name="TxtStatus"/>
    </Border>

    <TabControl x:Name="Tabs" Margin="10">

      <TabItem Header="  Inicio automático  ">
        <Grid Margin="12">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock x:Name="TxtAutoIntro" Grid.Row="0" Style="{StaticResource Intro}"/>
          <WrapPanel Grid.Row="1">
            <Button x:Name="BtnAutoScan" Style="{StaticResource Primary}" Content="Analizar"/>
            <CheckBox x:Name="ChkAutoRisk" Content="Mostrar solo lo que conviene revisar" Margin="8,6,16,8" IsChecked="True"/>
            <CheckBox x:Name="ChkAutoHideReviewed" Content="Ocultar lo que ya he revisado" Margin="0,6,16,8"/>
            <TextBlock Text="Buscar:" Margin="0,6,6,8"/>
            <TextBox x:Name="TxtAutoSearch" Width="220" Margin="0,3,0,8" Padding="3"/>
          </WrapPanel>
          <DataGrid x:Name="GridAuto" Grid.Row="2" RowStyle="{StaticResource RiskRow}">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Riesgo" Binding="{Binding Riesgo}" Width="95"/>
              <DataGridTextColumn Header="Tipo" Binding="{Binding Tipo}" Width="125"/>
              <DataGridTextColumn Header="Nombre" Binding="{Binding Nombre}" Width="250"/>
              <DataGridTextColumn Header="Estado" Binding="{Binding Estado}" Width="120"/>
              <DataGridTextColumn Header="Fabricante (firma)" Binding="{Binding Editor}" Width="170"/>
              <DataGridTextColumn Header="Firma" Binding="{Binding Firma}" Width="110"/>
              <DataGridTextColumn Header="Revisado" Binding="{Binding Revisado}" Width="70"/>
              <DataGridTextColumn Header="Archivo" Binding="{Binding Ruta}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <Border Grid.Row="3" Style="{StaticResource Detail}">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="300"/></Grid.ColumnDefinitions>
              <ScrollViewer Grid.Column="0" MaxHeight="210" VerticalScrollBarVisibility="Auto" Margin="0,0,12,0">
                <TextBlock x:Name="TxtAutoDetail" TextWrapping="Wrap"/>
              </ScrollViewer>
              <WrapPanel Grid.Column="1" VerticalAlignment="Top">
                <Button x:Name="BtnAutoKeep" Content="Mantener (lo reconozco)" ToolTip="Lo marca como revisado. No cambia nada en el PC."/>
                <Button x:Name="BtnAutoDisable" Content="Desactivar" ToolTip="Deja de arrancar solo, pero no se borra nada. Se puede deshacer."/>
                <Button x:Name="BtnAutoEnable" Content="Reactivar" ToolTip="Vuelve a activarlo."/>
                <Button x:Name="BtnAutoDelete" Style="{StaticResource Danger}" Content="Eliminar" ToolTip="Lo borra, guardando una copia para poder restaurarlo."/>
                <Button x:Name="BtnAutoOpen" Content="Abrir ubicación" ToolTip="Abre la carpeta donde está el archivo."/>
                <Button x:Name="BtnAutoSearch" Content="Buscar en internet" ToolTip="Busca qué es este programa."/>
                <Button x:Name="BtnAutoVT" Content="Comprobar en VirusTotal" ToolTip="Abre VirusTotal con la huella del archivo (no se sube el archivo)."/>
              </WrapPanel>
            </Grid>
          </Border>
        </Grid>
      </TabItem>

      <TabItem Header="  Procesos  ">
        <Grid Margin="12">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock x:Name="TxtProcIntro" Grid.Row="0" Style="{StaticResource Intro}"/>
          <WrapPanel Grid.Row="1">
            <Button x:Name="BtnProcScan" Style="{StaticResource Primary}" Content="Analizar procesos (5 segundos)"/>
            <CheckBox x:Name="ChkProcRisk" Content="Mostrar solo lo que conviene revisar" Margin="8,6,16,8"/>
          </WrapPanel>
          <DataGrid x:Name="GridProc" Grid.Row="2" RowStyle="{StaticResource RiskRow}">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Riesgo" Binding="{Binding Riesgo}" Width="95"/>
              <DataGridTextColumn Header="Proceso" Binding="{Binding Proceso}" Width="180"/>
              <DataGridTextColumn Header="PID" Binding="{Binding ProcId}" Width="65"/>
              <DataGridTextColumn Header="CPU %" Binding="{Binding CPU}" Width="70"/>
              <DataGridTextColumn Header="RAM (MB)" Binding="{Binding RAM}" Width="80"/>
              <DataGridTextColumn Header="Fabricante (firma)" Binding="{Binding Editor}" Width="190"/>
              <DataGridTextColumn Header="Firma" Binding="{Binding Firma}" Width="130"/>
              <DataGridTextColumn Header="Archivo" Binding="{Binding Ruta}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <Border Grid.Row="3" Style="{StaticResource Detail}">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="300"/></Grid.ColumnDefinitions>
              <ScrollViewer Grid.Column="0" MaxHeight="200" VerticalScrollBarVisibility="Auto" Margin="0,0,12,0">
                <TextBlock x:Name="TxtProcDetail" TextWrapping="Wrap"/>
              </ScrollViewer>
              <WrapPanel Grid.Column="1" VerticalAlignment="Top">
                <Button x:Name="BtnProcKill" Style="{StaticResource Danger}" Content="Finalizar proceso" ToolTip="Cierra el programa a la fuerza. Si vuelve a aparecer, revisa la pestaña Inicio automático."/>
                <Button x:Name="BtnProcOpen" Content="Abrir ubicación"/>
                <Button x:Name="BtnProcSearch" Content="Buscar en internet"/>
                <Button x:Name="BtnProcVT" Content="Comprobar en VirusTotal" ToolTip="Abre VirusTotal con la huella del archivo (no se sube el archivo)."/>
              </WrapPanel>
            </Grid>
          </Border>
        </Grid>
      </TabItem>

      <TabItem Header="  Seguridad  ">
        <Grid Margin="12">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock x:Name="TxtSecIntro" Grid.Row="0" Style="{StaticResource Intro}"/>
          <WrapPanel Grid.Row="1">
            <Button x:Name="BtnSecScan" Style="{StaticResource Primary}" Content="Comprobar"/>
            <Button x:Name="BtnSecDefender" Content="Abrir Seguridad de Windows"/>
            <TextBlock x:Name="TxtSecSummary" Margin="8,6,0,8" FontWeight="SemiBold"/>
          </WrapPanel>
          <DataGrid x:Name="GridSec" Grid.Row="2" RowStyle="{StaticResource StateRow}">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Estado" Binding="{Binding Estado}" Width="95"/>
              <DataGridTextColumn Header="Comprobación" Binding="{Binding Nombre}" Width="230"/>
              <DataGridTextColumn Header="Resultado" Binding="{Binding Detalle}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <Border Grid.Row="3" Style="{StaticResource Detail}">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="300"/></Grid.ColumnDefinitions>
              <ScrollViewer Grid.Column="0" MaxHeight="200" VerticalScrollBarVisibility="Auto" Margin="0,0,12,0">
                <TextBlock x:Name="TxtSecDetail" TextWrapping="Wrap"/>
              </ScrollViewer>
              <WrapPanel Grid.Column="1" VerticalAlignment="Top">
                <Button x:Name="BtnSecFix" Style="{StaticResource Primary}" Content="Solucionar"/>
              </WrapPanel>
            </Grid>
          </Border>
        </Grid>
      </TabItem>

      <TabItem Header="  Deshacer  ">
        <Grid Margin="12">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock x:Name="TxtUndoIntro" Grid.Row="0" Style="{StaticResource Intro}"/>
          <WrapPanel Grid.Row="1">
            <Button x:Name="BtnRestorePoint" Style="{StaticResource Primary}" Content="Crear punto de restauración"/>
            <Button x:Name="BtnOpenRstrui" Content="Abrir Restaurar sistema de Windows"/>
            <Button x:Name="BtnOpenBackups" Content="Abrir carpeta de copias"/>
          </WrapPanel>
          <DataGrid x:Name="GridUndo" Grid.Row="2" RowStyle="{StaticResource StateRow}">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Fecha" Binding="{Binding Fecha}" Width="145"/>
              <DataGridTextColumn Header="Módulo" Binding="{Binding Modulo}" Width="140"/>
              <DataGridTextColumn Header="Cambio" Binding="{Binding Descripcion}" Width="*"/>
              <DataGridTextColumn Header="Estado" Binding="{Binding Estado}" Width="120"/>
            </DataGrid.Columns>
          </DataGrid>
          <Border Grid.Row="3" Style="{StaticResource Detail}">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="300"/></Grid.ColumnDefinitions>
              <TextBlock x:Name="TxtUndoDetail" Grid.Column="0" TextWrapping="Wrap" Margin="0,0,12,0"/>
              <WrapPanel Grid.Column="1" VerticalAlignment="Top">
                <Button x:Name="BtnUndo" Style="{StaticResource Primary}" Content="Deshacer este cambio"/>
              </WrapPanel>
            </Grid>
          </Border>
        </Grid>
      </TabItem>

      <TabItem Header="  Ayuda  ">
        <ScrollViewer Margin="12" VerticalScrollBarVisibility="Auto">
          <TextBlock x:Name="TxtHelp" TextWrapping="Wrap" MaxWidth="900" HorizontalAlignment="Left"/>
        </ScrollViewer>
      </TabItem>

    </TabControl>
  </DockPanel>
</Window>
'@

# --- Textos de ayuda --------------------------------------------------------------------------
$script:TypeHelp = @{
    'Registro (Run)'   = 'Es una entrada del registro de Windows que abre un programa automáticamente al iniciar sesión. Es el sitio más habitual tanto para programas normales (Steam, Discord, el software del ratón...) como para malware.'
    'Carpeta Inicio'   = 'Es un archivo o acceso directo dentro de la carpeta Inicio de Windows. Todo lo que hay en esa carpeta se abre al iniciar sesión.'
    'Tarea programada' = 'Es una tarea del Programador de tareas: algo que Windows ejecuta solo al arrancar, al iniciar sesión o cada cierto tiempo. Los programas la usan para buscar actualizaciones; el malware, para volver a arrancar aunque cierres sus procesos. El minero de este PC usaba dos tareas (SysCheck2 y SysCheckX).'
    'Servicio'         = 'Es un servicio: un programa que funciona en segundo plano, sin ventana, normalmente con los máximos permisos. Muchos programas legítimos instalan uno (antitrampas de juegos, software de la placa base, actualizadores...).'
    'Driver'           = 'Es un controlador (driver): software de muy bajo nivel que permite a Windows comunicarse con el hardware. Desactivar el equivocado puede dejarte sin sonido, red o teclado, o incluso impedir que Windows arranque.'
    'WMI'              = 'Es una suscripción WMI: un mecanismo avanzado de Windows que ejecuta algo cuando ocurre un evento. En un PC doméstico casi nunca es legítimo.'
}
$script:RiskHelp = @{
    'Sospechoso' = 'Si no reconoces este programa, desactívalo (se puede deshacer) y compruébalo con "Buscar en internet" o "Comprobar en VirusTotal". Si se confirma que es malware, elimínalo y haz un análisis completo del antivirus.'
    'Revisar'    = 'Probablemente sea legítimo, pero comprueba que reconoces el programa. Si lo reconoces, pulsa "Mantener" para que deje de salir marcado.'
    'Resto'      = 'El programa al que apunta ya no existe. Es un resto inofensivo de algo desinstalado y se puede eliminar sin problema.'
    'Normal'     = 'Está firmado por un fabricante identificado. Si no necesitas que se abra al encender el PC, puedes desactivarlo para que arranque más rápido.'
}
$script:SigHelp = @{
    'Firmado'               = 'Tiene una firma digital válida: el fabricante indicado es quien lo creó y nadie lo ha modificado.'
    'Sin firma'             = 'No tiene firma digital: no hay forma de saber quién lo creó. Muchos programas pequeños no la tienen, pero el malware casi nunca la tiene.'
    'Firma alterada'        = 'El archivo se ha modificado después de firmarlo. Es muy mala señal.'
    'Firma no válida'       = 'Tiene una firma, pero no es válida (caducada, revocada o de origen no reconocido).'
    'Archivo no encontrado' = 'El archivo ya no existe.'
    'Sin ruta'              = 'No apunta a ningún archivo concreto.'
    'No se pudo comprobar'  = 'No se ha podido leer el archivo para comprobar su firma.'
}

function Get-IntroTexts {
    return @{
        Auto  = 'Aquí aparece todo lo que se pone en marcha solo al encender el PC o iniciar sesión: programas, tareas programadas, servicios y drivers que no son de Windows. Pulsa "Analizar", haz clic en una fila y lee la explicación de abajo antes de decidir. Colores: rojo = sospechoso, amarillo = conviene revisarlo, gris = restos de programas desinstalados, blanco = normal.'
        Proc  = 'Muestra los programas que se están ejecutando ahora, cuánta CPU consumen y si tienen firma digital. Algunos mineros se esconden cuando abres el Administrador de tareas; esta herramienta no se llama así, por lo que no la detectan. Ten el PC unos minutos sin tocar antes de analizar para pillarlos.'
        Sec   = 'Revisa los puntos que suele atacar el malware: el antivirus y sus exclusiones, bloqueos del sistema, el firewall, el archivo hosts... Haz clic en una comprobación para ver qué significa y, si hay un problema, pulsa el botón de la derecha para solucionarlo.'
        Undo  = 'Cada cambio que haces con esta herramienta queda apuntado aquí junto con una copia de seguridad, para poder deshacerlo. Además, puedes crear un punto de restauración de Windows: una "foto" del sistema a la que volver si algo sale mal.'
    }
}

function Get-HelpText {
    return @"
== Qué hace esta herramienta ==

$AppName te ayuda a revisar qué se ejecuta en tu PC sin necesidad de conocimientos técnicos. Nada se cambia sin que pulses un botón y confirmes, y todo lo que cambies queda guardado en la pestaña Deshacer.

== Cómo leer los colores ==

  Rojo (Sospechoso): tiene varias características típicas del malware. No significa que lo sea seguro, pero hay que mirarlo.
  Amarillo (Revisar): algo no cuadra del todo (por ejemplo, no tiene firma digital). Suele ser legítimo, pero conviene comprobarlo.
  Gris (Resto): apunta a un programa que ya no existe. Es inofensivo y se puede eliminar.
  Blanco (Normal): firmado por un fabricante conocido.

== Qué es la firma digital ==

Los programas serios llevan una firma digital, como un sello, que demuestra quién los ha hecho y que nadie los ha modificado. El malware casi nunca tiene una firma válida. Que algo no tenga firma no lo convierte en malware, pero es un motivo para revisarlo.

== Qué hace cada botón ==

  Mantener: lo marcas como revisado. No cambia nada. Si algún día el programa cambia, volverá a salir sin revisar.
  Desactivar: deja de arrancar solo, pero no se borra. Es la opción segura si tienes dudas.
  Reactivar: deshace una desactivación.
  Eliminar: lo borra, guardando antes una copia. Úsalo solo si estás seguro de que es malware o un resto.
  Buscar en internet / VirusTotal: para averiguar qué es. VirusTotal analiza el archivo con más de 70 antivirus; esta herramienta solo envía su huella (un código que lo identifica), no el archivo.

== Consejos de seguridad ==

  Descarga los programas solo desde su web oficial o desde Steam, Epic, EA, etc.
  No instales cracks, cheats, trainers ni "optimizadores" de webs desconocidas: son la forma más común de meter malware.
  Si dudas, desactiva en vez de eliminar.
  Si algo deja de funcionar después de un cambio, ve a la pestaña Deshacer.

== Si algo sale mal ==

  1. Pestaña Deshacer: selecciona el cambio y pulsa "Deshacer este cambio".
  2. Si Windows no arranca bien: reinicia y usa "Restaurar sistema" para volver al punto de restauración creado por esta herramienta.

== Privacidad ==

La herramienta no envía nada a internet por su cuenta. Solo abre el navegador cuando pulsas "Buscar en internet" o "Comprobar en VirusTotal". Los registros y copias se guardan en $($script:DataDir).

Versión $AppVersion
"@
}

# --- Utilidades de interfaz -------------------------------------------------------------------
function Update-UI {
    try { $script:UI.Window.Dispatcher.Invoke([Action] {}, [System.Windows.Threading.DispatcherPriority]::Background) } catch { }
}

function Set-Busy([string]$Message) {
    $script:UI.TxtStatus.Text = $Message
    $script:UI.Window.Cursor = [System.Windows.Input.Cursors]::Wait
    Update-UI
}

function Clear-Busy([string]$Message = 'Listo.') {
    $script:UI.TxtStatus.Text = $Message
    $script:UI.Window.Cursor = $null
}

function Show-Info([string]$Text) {
    [void][System.Windows.MessageBox]::Show($Text, $AppName, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
}

function Show-Error([string]$Text) {
    [void][System.Windows.MessageBox]::Show($Text, $AppName, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
}

function Ask-YesNo([string]$Text, [string]$Icon = 'Question') {
    $r = [System.Windows.MessageBox]::Show($Text, $AppName, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]$Icon)
    return ($r -eq [System.Windows.MessageBoxResult]::Yes)
}

function Invoke-Safe([scriptblock]$Action) {
    try { & $Action }
    catch { Clear-Busy 'Se produjo un error.'; Show-Error ("Se produjo un error:`n`n" + $_.Exception.Message) }
}

function Set-Detail($TextBlock, [object[]]$Segments) {
    $TextBlock.Inlines.Clear()
    foreach ($s in $Segments) {
        $run = New-Object System.Windows.Documents.Run ([string]$s.T)
        if ($s.B) { $run.FontWeight = [System.Windows.FontWeights]::SemiBold }
        $TextBlock.Inlines.Add($run)
    }
}
function S-B([string]$t) { return [pscustomobject]@{ T = $t; B = $true } }
function S-N([string]$t) { return [pscustomobject]@{ T = $t; B = $false } }

function New-Table([string[]]$Columns) {
    $t = New-Object System.Data.DataTable
    foreach ($c in $Columns) {
        $parts = $c.Split(':')
        if ($parts.Count -gt 1) {
            switch ($parts[1]) { 'int' { [void]$t.Columns.Add($parts[0], [int]) } 'double' { [void]$t.Columns.Add($parts[0], [double]) } default { [void]$t.Columns.Add($parts[0]) } }
        } else { [void]$t.Columns.Add($c) }
    }
    return , $t
}

function ConvertTo-LikeSafe([string]$Text) {
    $Text = $Text -replace "'", "''"
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        if ('[]*%'.IndexOf($ch) -ge 0) { [void]$sb.Append('[').Append($ch).Append(']') } else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function Open-Location([string]$Path) {
    if (Test-FileQuiet $Path) { Start-Process explorer.exe ('/select,"' + $Path + '"') }
    else { Show-Info 'El archivo no existe, así que no se puede abrir su ubicación.' }
}

function Search-Web([string]$Name, [string]$Path) {
    $leaf = ''
    if ($Path) { try { $leaf = [IO.Path]::GetFileName($Path) } catch { } }
    $q = ("$leaf $Name").Trim() + ' qué es'
    Start-Process ('https://www.google.com/search?q=' + [uri]::EscapeDataString($q))
}

function Open-VirusTotal([string]$Path) {
    if (-not (Test-FileQuiet $Path)) { Show-Info 'El archivo no existe, así que no se puede comprobar.'; return }
    $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    Start-Process ('https://www.virustotal.com/gui/file/' + $h)
}

function Confirm-FirstChange {
    if ($script:RestoreChecked) { return }
    $script:RestoreChecked = $true
    $msg = "Antes del primer cambio es recomendable crear un punto de restauración de Windows: una copia del estado del sistema a la que volver si algo sale mal.`n`n¿Quieres crearlo ahora? Tarda menos de un minuto."
    if (Ask-YesNo $msg) {
        Set-Busy 'Creando punto de restauración...'
        try { New-RestorePoint; Clear-Busy 'Punto de restauración creado.' }
        catch { Clear-Busy; Show-Error ("No se pudo crear el punto de restauración: " + $_.Exception.Message + "`n`nPuedes seguir igualmente: los cambios de esta herramienta se pueden deshacer desde la pestaña Deshacer.") }
    }
}

# --- Pestaña: Inicio automático ---------------------------------------------------------------
function Update-AutoGrid {
    $t = New-Table @('Id', 'Orden:int', 'Riesgo', 'Tipo', 'Nombre', 'Estado', 'Editor', 'Firma', 'Revisado', 'Ruta')
    $script:AutoById = @{}
    foreach ($e in $script:AutoList) {
        $script:AutoById[$e.Id] = $e
        $r = $t.NewRow()
        $r['Id'] = $e.Id; $r['Orden'] = (Get-RiskOrder $e.Riesgo); $r['Riesgo'] = $e.Riesgo; $r['Tipo'] = $e.Tipo
        $r['Nombre'] = $e.Nombre; $r['Estado'] = $e.Estado; $r['Editor'] = "$($e.Editor)"; $r['Firma'] = $e.Firma
        $rev = ''; if ($script:Reviewed.Contains($e.Id)) { $rev = 'Sí' }
        $r['Revisado'] = $rev; $r['Ruta'] = "$($e.Ruta)"
        $t.Rows.Add($r)
    }
    $t.DefaultView.Sort = 'Orden ASC, Tipo ASC, Nombre ASC'
    $script:AutoTable = $t
    $script:UI.GridAuto.ItemsSource = $t.DefaultView
    Set-AutoFilter
}

function Set-AutoFilter {
    if (-not $script:AutoTable) { return }
    $parts = @()
    if ($script:UI.ChkAutoRisk.IsChecked) { $parts += "Riesgo <> 'Normal'" }
    if ($script:UI.ChkAutoHideReviewed.IsChecked) { $parts += "Revisado <> 'Sí'" }
    $q = $script:UI.TxtAutoSearch.Text
    if ($q) {
        $s = ConvertTo-LikeSafe $q
        $parts += "(Nombre LIKE '%$s%' OR Ruta LIKE '%$s%' OR Editor LIKE '%$s%' OR Tipo LIKE '%$s%')"
    }
    $script:AutoTable.DefaultView.RowFilter = ($parts -join ' AND ')
    $total = $script:AutoList.Count
    $sus = @($script:AutoList | Where-Object { $_.Riesgo -eq 'Sospechoso' }).Count
    $rev = @($script:AutoList | Where-Object { $_.Riesgo -eq 'Revisar' }).Count
    $res = @($script:AutoList | Where-Object { $_.Riesgo -eq 'Resto' }).Count
    $script:UI.TxtStatus.Text = "Inicio automático: $total elementos · $sus sospechosos · $rev para revisar · $res restos. Mostrando $($script:AutoTable.DefaultView.Count)."
}

function Get-SelectedAuto {
    $sel = $script:UI.GridAuto.SelectedItem
    if (-not $sel) { return $null }
    $id = [string]$sel.Row['Id']
    if ($script:AutoById.ContainsKey($id)) { return $script:AutoById[$id] }
    return $null
}

function Show-AutoDetail {
    $e = Get-SelectedAuto
    foreach ($b in @('BtnAutoKeep', 'BtnAutoDisable', 'BtnAutoEnable', 'BtnAutoDelete', 'BtnAutoOpen', 'BtnAutoSearch', 'BtnAutoVT')) { $script:UI[$b].IsEnabled = $false }
    if (-not $e) {
        Set-Detail $script:UI.TxtAutoDetail @((S-N 'Selecciona una fila de la tabla para ver aquí qué es, por qué está marcada y qué te recomendamos hacer.'))
        return
    }
    $seg = @()
    $seg += S-B ($e.Nombre + "`n")
    $seg += S-N ($e.Tipo + ' · ' + $e.Origen + "`n`n")
    $seg += S-B 'Qué es: '; $seg += S-N ($script:TypeHelp[$e.Tipo] + "`n`n")
    $seg += S-B 'Comando: '; $seg += S-N ($e.Comando + "`n")
    $seg += S-B 'Archivo: '; $seg += S-N ($e.Ruta + "`n")
    $sigText = $e.Firma
    if ($e.Editor) { $sigText += ' (' + $e.Editor + ')' }
    $seg += S-B 'Firma digital: '; $seg += S-N ($sigText + '. ' + $script:SigHelp[$e.Firma] + "`n`n")
    if ($e.Motivos -and @($e.Motivos).Count -gt 0) {
        $seg += S-B "Por qué está marcado:`n"
        foreach ($mo in $e.Motivos) { $seg += S-N ('  - ' + $mo + "`n") }
        $seg += S-N "`n"
    }
    $seg += S-B 'Recomendación: '; $seg += S-N $script:RiskHelp[$e.Riesgo]
    if ($e.EsMicrosoft) { $seg += S-N "`n`nAviso: está firmado por Microsoft. Tocarlo puede hacer que Windows funcione mal." }
    Set-Detail $script:UI.TxtAutoDetail $seg

    $acc = @($e.Acciones)
    $script:UI.BtnAutoKeep.IsEnabled    = $true
    $script:UI.BtnAutoDisable.IsEnabled = ($acc -contains 'Desactivar') -and ($e.Estado -like 'Activo*')
    $script:UI.BtnAutoEnable.IsEnabled  = ($acc -contains 'Desactivar') -and ($e.Estado -eq 'Desactivado')
    $script:UI.BtnAutoDelete.IsEnabled  = ($acc -contains 'Eliminar')
    $script:UI.BtnAutoOpen.IsEnabled    = [bool]$e.Existe
    $script:UI.BtnAutoSearch.IsEnabled  = $true
    $script:UI.BtnAutoVT.IsEnabled      = [bool]$e.Existe
}

function Start-AutoScan {
    $script:SigCache = @{}
    Set-Busy 'Analizando...'
    $script:AutoList = @(Get-AutostartEntries { param($m) Set-Busy $m })
    Update-AutoGrid
    Clear-Busy $script:UI.TxtStatus.Text
    $script:UI.Window.Cursor = $null
    Show-AutoDetail
}

function Invoke-AutoUserAction([string]$Action) {
    $e = Get-SelectedAuto
    if (-not $e) { return }
    switch ($Action) {
        'Desactivar' { $msg = "Vas a DESACTIVAR:`n`n$($e.Nombre)`n`nDejará de arrancar solo, pero no se borra nada. Puedes deshacerlo en cualquier momento desde la pestaña Deshacer.`n`n¿Continuar?" }
        'Activar'    { $msg = "Vas a REACTIVAR:`n`n$($e.Nombre)`n`n¿Continuar?" }
        'Eliminar'   { $msg = "Vas a ELIMINAR:`n`n$($e.Nombre)`n`nSe guardará una copia para poder restaurarlo, pero úsalo solo si estás seguro de que es malware o un resto. Si tienes dudas, mejor usa Desactivar.`n`n¿Continuar?" }
    }
    if ($e.EsMicrosoft) { $msg += "`n`nAtención: este elemento está firmado por Microsoft. Tocarlo puede hacer que Windows funcione mal." }
    if ($e.Tipo -eq 'Driver') { $msg += "`n`nAtención: es un driver. Si desactivas uno necesario (sonido, red, almacenamiento...), ese hardware dejará de funcionar o Windows podría no arrancar." }
    if ($e.Tipo -eq 'WMI') { $msg += "`n`nLas suscripciones WMI no se pueden restaurar automáticamente; se guardará una copia en texto." }
    $icon = 'Question'; if ($Action -eq 'Eliminar' -or $e.EsMicrosoft -or $e.Tipo -eq 'Driver') { $icon = 'Warning' }
    if (-not (Ask-YesNo $msg $icon)) { return }
    Confirm-FirstChange
    Set-Busy "$Action..."
    Invoke-AutoAction $e $Action
    if ($Action -eq 'Eliminar') { $script:AutoList = @($script:AutoList | Where-Object { $_.Id -ne $e.Id }) }
    elseif ($Action -eq 'Desactivar') { $e.Estado = 'Desactivado' }
    else { $e.Estado = 'Activo' }
    Update-AutoGrid
    Update-UndoGrid
    Clear-Busy "Hecho: $Action · $($e.Nombre)"
    Show-AutoDetail
}

function Invoke-AutoKeep {
    $e = Get-SelectedAuto
    if (-not $e) { return }
    [void]$script:Reviewed.Add($e.Id)
    Save-Reviewed
    Update-AutoGrid
    $script:UI.TxtStatus.Text = "Marcado como revisado: $($e.Nombre)"
}

# --- Pestaña: Procesos ------------------------------------------------------------------------
function Update-ProcGrid {
    $t = New-Table @('Id', 'Orden:int', 'Riesgo', 'Proceso', 'ProcId:int', 'CPU:double', 'RAM:int', 'Editor', 'Firma', 'Ruta')
    $script:ProcById = @{}
    foreach ($p in $script:ProcList) {
        $script:ProcById[$p.Id] = $p
        $r = $t.NewRow()
        $r['Id'] = $p.Id; $r['Orden'] = (Get-RiskOrder $p.Riesgo); $r['Riesgo'] = $p.Riesgo; $r['Proceso'] = $p.Proceso
        $r['ProcId'] = [int]$p.ProcId; $r['CPU'] = [double]$p.CPU; $r['RAM'] = [int]$p.RAM
        $r['Editor'] = "$($p.Editor)"; $r['Firma'] = $p.Firma; $r['Ruta'] = $p.Ruta
        $t.Rows.Add($r)
    }
    $t.DefaultView.Sort = 'Orden ASC, CPU DESC'
    $script:ProcTable = $t
    $script:UI.GridProc.ItemsSource = $t.DefaultView
    Set-ProcFilter
}

function Set-ProcFilter {
    if (-not $script:ProcTable) { return }
    if ($script:UI.ChkProcRisk.IsChecked) { $script:ProcTable.DefaultView.RowFilter = "Riesgo <> 'Normal'" }
    else { $script:ProcTable.DefaultView.RowFilter = '' }
}

function Get-SelectedProc {
    $sel = $script:UI.GridProc.SelectedItem
    if (-not $sel) { return $null }
    $id = [string]$sel.Row['Id']
    if ($script:ProcById.ContainsKey($id)) { return $script:ProcById[$id] }
    return $null
}

function Show-ProcDetail {
    $p = Get-SelectedProc
    foreach ($b in @('BtnProcKill', 'BtnProcOpen', 'BtnProcSearch', 'BtnProcVT')) { $script:UI[$b].IsEnabled = $false }
    if (-not $p) {
        Set-Detail $script:UI.TxtProcDetail @((S-N 'Selecciona un proceso para ver aquí qué es y por qué está marcado.'))
        return
    }
    $seg = @()
    $seg += S-B ($p.Proceso + ' (PID ' + $p.ProcId + ")`n")
    $seg += S-N ("CPU: $($p.CPU) % · RAM: $($p.RAM) MB`n`n")
    $seg += S-B 'Archivo: '; $seg += S-N ($p.Ruta + "`n")
    $seg += S-B 'Comando: '; $seg += S-N ($p.Comando + "`n")
    $sigText = $p.Firma; if ($p.Editor) { $sigText += ' (' + $p.Editor + ')' }
    $help = $script:SigHelp[$p.Firma]; if (-not $help) { $help = 'Windows protege este proceso y no deja leer sus datos; suele ser parte del sistema.' }
    $seg += S-B 'Firma digital: '; $seg += S-N ($sigText + '. ' + $help + "`n`n")
    if ($p.Motivos -and @($p.Motivos).Count -gt 0) {
        $seg += S-B "Por qué está marcado:`n"
        foreach ($mo in $p.Motivos) { $seg += S-N ('  - ' + $mo + "`n") }
        $seg += S-N "`n"
    }
    $seg += S-B 'Recomendación: '
    switch ($p.Riesgo) {
        'Sospechoso' { $seg += S-N 'Compruébalo con "Buscar en internet" o "VirusTotal". Si es malware, finalízalo y busca en la pestaña Inicio automático qué lo arranca; si no, volverá al reiniciar.' }
        'Revisar'    { $seg += S-N 'Probablemente sea legítimo. Comprueba que reconoces el programa.' }
        default      { $seg += S-N 'No hay nada raro en este proceso.' }
    }
    Set-Detail $script:UI.TxtProcDetail $seg
    $script:UI.BtnProcKill.IsEnabled   = $true
    $script:UI.BtnProcOpen.IsEnabled   = [bool]$p.Existe
    $script:UI.BtnProcSearch.IsEnabled = $true
    $script:UI.BtnProcVT.IsEnabled     = [bool]$p.Existe
}

function Start-ProcScan {
    $script:SigCache = @{}
    Set-Busy 'Midiendo el uso de CPU durante 5 segundos... (no toques el PC)'
    $script:ProcList = @(Get-ProcessScan 5)
    Update-ProcGrid
    $sus = @($script:ProcList | Where-Object { $_.Riesgo -eq 'Sospechoso' }).Count
    $rev = @($script:ProcList | Where-Object { $_.Riesgo -eq 'Revisar' }).Count
    $cpu = 0; foreach ($p in $script:ProcList) { $cpu += $p.CPU }
    Clear-Busy ("Procesos: $($script:ProcList.Count) · $sus sospechosos · $rev para revisar · CPU total aproximada: " + [math]::Round($cpu, 1) + ' %')
    Show-ProcDetail
}

function Invoke-ProcKill {
    $p = Get-SelectedProc
    if (-not $p) { return }
    if (-not (Ask-YesNo "¿Finalizar el proceso $($p.Proceso) (PID $($p.ProcId))?`n`nSe cerrará a la fuerza y se perderá lo que no esté guardado en ese programa. Si es parte de Windows, el PC podría volverse inestable hasta reiniciar." 'Warning')) { return }
    Stop-Process -Id $p.ProcId -Force -ErrorAction Stop
    Add-ChangeLog 'Procesos' "Proceso finalizado: $($p.Proceso) ($($p.Ruta))" 'NoReversible' @{}
    $script:ProcList = @($script:ProcList | Where-Object { $_.Id -ne $p.Id })
    Update-ProcGrid
    Update-UndoGrid
    $script:UI.TxtStatus.Text = "Proceso finalizado: $($p.Proceso)"
}

# --- Pestaña: Seguridad -----------------------------------------------------------------------
function Update-SecGrid {
    $t = New-Table @('Id', 'Orden:int', 'Estado', 'Nombre', 'Detalle')
    $script:SecById = @{}
    foreach ($c in $script:SecList) {
        $script:SecById[$c.Id] = $c
        $r = $t.NewRow()
        $r['Id'] = $c.Id; $r['Orden'] = (Get-StateOrder $c.Estado); $r['Estado'] = $c.Estado; $r['Nombre'] = $c.Nombre; $r['Detalle'] = $c.Detalle
        $t.Rows.Add($r)
    }
    $t.DefaultView.Sort = 'Orden ASC'
    $script:SecTable = $t
    $script:UI.GridSec.ItemsSource = $t.DefaultView
    $pr = @($script:SecList | Where-Object { $_.Estado -eq 'Problema' }).Count
    $at = @($script:SecList | Where-Object { $_.Estado -eq 'Atención' }).Count
    if ($pr -eq 0 -and $at -eq 0) { $script:UI.TxtSecSummary.Text = 'Todo correcto.' }
    else { $script:UI.TxtSecSummary.Text = "$pr problema(s) y $at aviso(s)." }
}

function Get-SelectedSec {
    $sel = $script:UI.GridSec.SelectedItem
    if (-not $sel) { return $null }
    $id = [string]$sel.Row['Id']
    if ($script:SecById.ContainsKey($id)) { return $script:SecById[$id] }
    return $null
}

function Show-SecDetail {
    $c = Get-SelectedSec
    $script:UI.BtnSecFix.IsEnabled = $false
    $script:UI.BtnSecFix.Content = 'Solucionar'
    if (-not $c) {
        Set-Detail $script:UI.TxtSecDetail @((S-N 'Selecciona una comprobación para ver qué significa.'))
        return
    }
    $seg = @()
    $seg += S-B ($c.Nombre + ': ' + $c.Estado + "`n`n")
    $seg += S-B 'Resultado: '; $seg += S-N ($c.Detalle + "`n`n")
    $seg += S-B 'Qué es: '; $seg += S-N $c.Explicacion
    Set-Detail $script:UI.TxtSecDetail $seg
    if ($c.AccionTexto) {
        $script:UI.BtnSecFix.Content = $c.AccionTexto
        $script:UI.BtnSecFix.IsEnabled = $true
    }
}

function Start-SecScan {
    Set-Busy 'Comprobando la seguridad del equipo...'
    $script:SecList = @(Get-SecurityChecks)
    Update-SecGrid
    Clear-Busy 'Comprobación de seguridad terminada.'
    Show-SecDetail
}

function Invoke-SecFix {
    $c = Get-SelectedSec
    if (-not $c) { return }
    $mod = 'Seguridad'
    switch ($c.Id) {
        'av'     { Start-Process 'windowsdefender:'; return }
        'tamper' { Start-Process 'windowsdefender://threatsettings'; return }
        'hosts'  { Start-Process notepad.exe (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'); return }
        'sb'     { Show-Info "El arranque seguro se activa en la BIOS, no desde Windows.`n`nEn placas MSI: entra en la BIOS con Supr al encender, pulsa F7 y ve a Settings > Advanced > Windows OS Configuration. Pon 'BIOS CSM/UEFI Mode' en UEFI y después activa 'Secure Boot'. Guarda con F10.`n`nImportante: Windows debe estar instalado en modo UEFI (disco GPT). Si el PC arranca en modo antiguo, primero hay que convertir el disco."; return }
        'tpm'    { Show-Info "El TPM se activa en la BIOS, no desde Windows.`n`nEn placas MSI con Ryzen: entra en la BIOS con Supr al encender, pulsa F7 y ve a Settings > Security > Trusted Computing. Pon 'Security Device Support' en Enabled y 'AMD fTPM switch' en 'AMD CPU fTPM'. Guarda con F10."; return }
        'firmas' {
            Set-Busy 'Actualizando las firmas del antivirus...'
            Update-MpSignature -ErrorAction Stop
            Clear-Busy 'Firmas actualizadas.'
        }
        'scan'   {
            Start-Process powershell.exe -WindowStyle Minimized -ArgumentList '-NoProfile -Command Start-MpScan -ScanType QuickScan'
            Show-Info 'El análisis rápido se está ejecutando en segundo plano. Verás el resultado en Seguridad de Windows > Protección antivirus y contra amenazas.'
            return
        }
        'excl'   {
            $n = 0
            foreach ($x in @($c.Datos)) {
                if (Ask-YesNo ("¿Quitar esta exclusión del antivirus?`n`n$($x.Texto)`n`nSi la pusiste tú a propósito (por ejemplo, para una carpeta de juegos), contesta No.") 'Warning') {
                    switch ($x.Clase) {
                        'Path'      { Remove-MpPreference -ExclusionPath $x.Valor -ErrorAction Stop }
                        'Process'   { Remove-MpPreference -ExclusionProcess $x.Valor -ErrorAction Stop }
                        'Extension' { Remove-MpPreference -ExclusionExtension $x.Valor -ErrorAction Stop }
                    }
                    Add-ChangeLog $mod "Exclusión del antivirus quitada: $($x.Texto)" 'Exclusion' @{ Clase = $x.Clase; Valor = $x.Valor }
                    $n++
                }
            }
            $script:UI.TxtStatus.Text = "Exclusiones quitadas: $n"
        }
        'pol'    {
            foreach ($x in @($c.Datos)) {
                if (Ask-YesNo ("¿Quitar este bloqueo?`n`n$($x.Texto)") 'Warning') {
                    Remove-RegValueLogged $mod "Bloqueo quitado: $($x.Texto)" $x.Key $x.Name
                }
            }
        }
        'winlogon' {
            if (-not (Ask-YesNo 'Se restaurarán los valores originales de Windows (explorer.exe y userinit.exe). ¿Continuar?' 'Warning')) { return }
            Confirm-FirstChange
            $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-RegValueLogged $mod 'Winlogon: Shell restaurado a explorer.exe' $wl 'Shell' 'explorer.exe' 'String'
            Set-RegValueLogged $mod 'Winlogon: Userinit restaurado' $wl 'Userinit' ($env:SystemRoot + '\system32\userinit.exe,') 'String'
        }
        'uac'    {
            Set-RegValueLogged $mod 'Control de cuentas (UAC) activado' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1 'DWord'
            Show-Info 'Control de cuentas activado. Reinicia el PC para que se aplique.'
        }
        'fw'     {
            foreach ($perfil in @($c.Datos)) {
                Set-NetFirewallProfile -Name $perfil -Enabled True -ErrorAction Stop
                Add-ChangeLog $mod "Firewall activado en el perfil $perfil" 'Firewall' @{ Perfil = $perfil }
            }
        }
        'proxy'  {
            if (-not (Ask-YesNo 'Se desactivará el proxy de internet. Si lo usas a propósito (por ejemplo, en una red de empresa), contesta No. ¿Continuar?')) { return }
            $is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            Set-RegValueLogged $mod 'Proxy de internet desactivado' $is 'ProxyEnable' 0 'DWord'
            $pac = (Get-ItemProperty -LiteralPath $is -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
            if ($pac) { Remove-RegValueLogged $mod 'Script de proxy automático quitado' $is 'AutoConfigURL' }
        }
    }
    Update-UndoGrid
    Start-SecScan
}

# --- Pestaña: Deshacer ------------------------------------------------------------------------
function Update-UndoGrid {
    $t = New-Table @('Id', 'Fecha', 'Modulo', 'Descripcion', 'Estado')
    $script:UndoList = @(Read-JsonList $script:LogFile)
    $script:UndoById = @{}
    foreach ($c in $script:UndoList) {
        $script:UndoById[$c.Id] = $c
        $estado = 'Aplicado'
        if ($c.Deshecho) { $estado = 'Deshecho' }
        elseif ($c.Tipo -eq 'Info') { $estado = 'Informativo' }
        elseif ($script:ReversibleTypes -notcontains $c.Tipo) { $estado = 'No reversible' }
        $r = $t.NewRow()
        $r['Id'] = $c.Id; $r['Fecha'] = $c.Fecha; $r['Modulo'] = $c.Modulo; $r['Descripcion'] = $c.Descripcion; $r['Estado'] = $estado
        $t.Rows.Add($r)
    }
    $t.DefaultView.Sort = 'Fecha DESC'
    $script:UndoTable = $t
    $script:UI.GridUndo.ItemsSource = $t.DefaultView
    Show-UndoDetail
}

function Get-SelectedUndo {
    $sel = $script:UI.GridUndo.SelectedItem
    if (-not $sel) { return $null }
    $id = [string]$sel.Row['Id']
    if ($script:UndoById.ContainsKey($id)) { return $script:UndoById[$id] }
    return $null
}

function Show-UndoDetail {
    $c = Get-SelectedUndo
    $script:UI.BtnUndo.IsEnabled = $false
    if (-not $c) {
        $script:UI.TxtUndoDetail.Text = 'Selecciona un cambio para deshacerlo. Los cambios más recientes aparecen arriba.'
        return
    }
    $txt = "$($c.Fecha) · $($c.Modulo)`n$($c.Descripcion)`n`n"
    if ($c.Deshecho) { $txt += 'Este cambio ya se deshizo.' }
    elseif ($c.Tipo -eq 'Info') { $txt += 'Es solo un aviso informativo; no hay nada que deshacer.' }
    elseif ($script:ReversibleTypes -notcontains $c.Tipo) { $txt += 'Este cambio no se puede deshacer automáticamente.' }
    else {
        $txt += 'Pulsa "Deshacer este cambio" para dejarlo como estaba.'
        if ($c.Tipo -eq 'ServicioEliminado') { $txt += ' En el caso de un servicio eliminado, hay que reiniciar el PC después.' }
        $script:UI.BtnUndo.IsEnabled = $true
    }
    $script:UI.TxtUndoDetail.Text = $txt
}

function Invoke-UndoSelected {
    $c = Get-SelectedUndo
    if (-not $c) { return }
    if (-not (Ask-YesNo "¿Deshacer este cambio?`n`n$($c.Descripcion)")) { return }
    Undo-Change $c
    Update-UndoGrid
    $script:UI.TxtStatus.Text = "Cambio deshecho: $($c.Descripcion)"
    if ($c.Tipo -eq 'ServicioEliminado') { Show-Info 'Servicio restaurado. Reinicia el PC para que vuelva a funcionar.' }
}

# --- Arranque de la ventana -------------------------------------------------------------------
function Start-RigWarden {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Data
    Initialize-DataDir
    Load-Reviewed

    [xml]$xml = $script:Xaml
    $reader = New-Object System.Xml.XmlNodeReader $xml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $script:UI = @{ Window = $window }
    foreach ($node in $xml.SelectNodes('//*[@*[local-name()="Name"]]')) {
        $name = $node.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1
        if ($name) { $script:UI[$name.Value] = $window.FindName($name.Value) }
    }

    $window.Title = "$AppName $AppVersion"
    $script:UI.TxtTitle.Text = $AppName
    $script:UI.TxtSubtitle.Text = 'Vigila lo que se ejecuta en tu PC, entiende qué es y decide tú. Todo se puede deshacer.'
    $intro = Get-IntroTexts
    $script:UI.TxtAutoIntro.Text = $intro.Auto
    $script:UI.TxtProcIntro.Text = $intro.Proc
    $script:UI.TxtSecIntro.Text  = $intro.Sec
    $script:UI.TxtUndoIntro.Text = $intro.Undo
    $script:UI.TxtHelp.Text      = Get-HelpText
    $script:UI.TxtStatus.Text    = 'Listo. Empieza por la pestaña "Inicio automático" y pulsa "Analizar".'

    # Inicio automático
    $script:UI.BtnAutoScan.Add_Click({ Invoke-Safe { Start-AutoScan } })
    $script:UI.GridAuto.Add_SelectionChanged({ Invoke-Safe { Show-AutoDetail } })
    $script:UI.ChkAutoRisk.Add_Click({ Invoke-Safe { Set-AutoFilter } })
    $script:UI.ChkAutoHideReviewed.Add_Click({ Invoke-Safe { Set-AutoFilter } })
    $script:UI.TxtAutoSearch.Add_TextChanged({ Invoke-Safe { Set-AutoFilter } })
    $script:UI.BtnAutoKeep.Add_Click({ Invoke-Safe { Invoke-AutoKeep } })
    $script:UI.BtnAutoDisable.Add_Click({ Invoke-Safe { Invoke-AutoUserAction 'Desactivar' } })
    $script:UI.BtnAutoEnable.Add_Click({ Invoke-Safe { Invoke-AutoUserAction 'Activar' } })
    $script:UI.BtnAutoDelete.Add_Click({ Invoke-Safe { Invoke-AutoUserAction 'Eliminar' } })
    $script:UI.BtnAutoOpen.Add_Click({ Invoke-Safe { $e = Get-SelectedAuto; if ($e) { Open-Location $e.Ruta } } })
    $script:UI.BtnAutoSearch.Add_Click({ Invoke-Safe { $e = Get-SelectedAuto; if ($e) { Search-Web $e.Nombre $e.Ruta } } })
    $script:UI.BtnAutoVT.Add_Click({ Invoke-Safe { $e = Get-SelectedAuto; if ($e) { Open-VirusTotal $e.Ruta } } })

    # Procesos
    $script:UI.BtnProcScan.Add_Click({ Invoke-Safe { Start-ProcScan } })
    $script:UI.GridProc.Add_SelectionChanged({ Invoke-Safe { Show-ProcDetail } })
    $script:UI.ChkProcRisk.Add_Click({ Invoke-Safe { Set-ProcFilter } })
    $script:UI.BtnProcKill.Add_Click({ Invoke-Safe { Invoke-ProcKill } })
    $script:UI.BtnProcOpen.Add_Click({ Invoke-Safe { $p = Get-SelectedProc; if ($p) { Open-Location $p.Ruta } } })
    $script:UI.BtnProcSearch.Add_Click({ Invoke-Safe { $p = Get-SelectedProc; if ($p) { Search-Web $p.Proceso $p.Ruta } } })
    $script:UI.BtnProcVT.Add_Click({ Invoke-Safe { $p = Get-SelectedProc; if ($p) { Open-VirusTotal $p.Ruta } } })

    # Seguridad
    $script:UI.BtnSecScan.Add_Click({ Invoke-Safe { Start-SecScan } })
    $script:UI.GridSec.Add_SelectionChanged({ Invoke-Safe { Show-SecDetail } })
    $script:UI.BtnSecFix.Add_Click({ Invoke-Safe { Invoke-SecFix } })
    $script:UI.BtnSecDefender.Add_Click({ Invoke-Safe { Start-Process 'windowsdefender:' } })

    # Deshacer
    $script:UI.GridUndo.Add_SelectionChanged({ Invoke-Safe { Show-UndoDetail } })
    $script:UI.BtnUndo.Add_Click({ Invoke-Safe { Invoke-UndoSelected } })
    $script:UI.BtnRestorePoint.Add_Click({ Invoke-Safe {
        Set-Busy 'Creando punto de restauración...'
        New-RestorePoint
        Clear-Busy 'Punto de restauración creado.'
        $script:RestoreChecked = $true
        Update-UndoGrid
        Show-Info 'Punto de restauración creado correctamente.'
    } })
    $script:UI.BtnOpenRstrui.Add_Click({ Invoke-Safe { Start-Process rstrui.exe } })
    $script:UI.BtnOpenBackups.Add_Click({ Invoke-Safe { Start-Process explorer.exe $script:BackupDir } })

    Show-AutoDetail
    Show-ProcDetail
    Show-SecDetail
    Update-UndoGrid

    [void]$window.ShowDialog()
}

# ----------------------------------------------------------------------------------------------
#  Punto de entrada
# ----------------------------------------------------------------------------------------------
if (-not (Test-Admin)) {
    Write-Host "$AppName necesita permisos de administrador. Acepta el aviso de Windows que va a aparecer." -ForegroundColor Yellow
    Remove-Item Env:RIGWARDEN_UTF8 -ErrorAction SilentlyContinue
    if ($PSCommandPath) { $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" }
    else { $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"irm '$RepoRawUrl' | iex`"" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
} elseif ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Write-Host 'Reiniciando en modo compatible con ventanas...' -ForegroundColor Yellow
    if ($PSCommandPath) { $arguments = "-STA -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" }
    else { $arguments = "-STA -NoProfile -ExecutionPolicy Bypass -Command `"irm '$RepoRawUrl' | iex`"" }
    Start-Process powershell.exe -ArgumentList $arguments
} else {
    Write-Host "Abriendo $AppName $AppVersion... (no cierres esta ventana mientras la uses)" -ForegroundColor Cyan
    Start-RigWarden
}
