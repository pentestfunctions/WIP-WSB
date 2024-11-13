# Create working directory
$toolsDir = "C:\SecurityTools"
try {
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    Set-Location $toolsDir
    Write-Host "Created SecurityTools directory at $toolsDir"
} catch {
    $errorMessage = $_.Exception.Message
    Write-Host "Error creating directory: $errorMessage"
    exit 1
}

# Function to download file
function Start-Download {
    param (
        [string]$name,
        [string]$url,
        [string]$outputFile
    )
    
    Write-Host "Starting download of $name..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $outputFile)
        Write-Host "Successfully downloaded $name to $outputFile"
        return $true
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "Error downloading $name`: $errorMessage"
        return $false
    }
}

# Function to extract zip
function Extract-Tool {
    param (
        [string]$name,
        [string]$zipFile,
        [string]$extractDir = ""
    )
    
    try {
        Write-Host "Extracting $name from $zipFile to $extractDir..."
        if ($extractDir -eq "") { 
            $extractDir = [System.IO.Path]::GetFileNameWithoutExtension($zipFile) 
        }
        Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force
        Remove-Item $zipFile
        Write-Host "Extracted $name to $extractDir"
        return $true
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "Error extracting $name`: $errorMessage"
        return $false
    }
}

# Install Visual C++ Redistributables
Write-Host "Installing Visual C++ Redistributables..."
$vcRedists = @(
    @{
        name = "VC++ 2015-2022 x64"
        url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        file = (Join-Path $toolsDir "vc_redist.x64.exe")
    },
    @{
        name = "VC++ 2015-2022 x86"
        url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
        file = (Join-Path $toolsDir "vc_redist.x86.exe")
    }
)

foreach ($vcRedist in $vcRedists) {
    if (Start-Download -name $vcRedist.name -url $vcRedist.url -outputFile $vcRedist.file) {
        Write-Host "Installing $($vcRedist.name)..."
        Start-Process -Wait -FilePath $vcRedist.file -ArgumentList "/install /quiet /norestart" -NoNewWindow
        Remove-Item $vcRedist.file -Force -ErrorAction SilentlyContinue
    }
}

# Download and extract FeroxBuster
Write-Host "Setting up FeroxBuster..."
$feroxUrl = "https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86-windows-feroxbuster.exe.zip"
$feroxZip = Join-Path $toolsDir "feroxbuster.zip"
$feroxDir = Join-Path $toolsDir "feroxbuster"
if (Start-Download -name "FeroxBuster" -url $feroxUrl -outputFile $feroxZip) {
    Extract-Tool -name "FeroxBuster" -zipFile $feroxZip -extractDir $feroxDir
}

# Download and extract RustScan
Write-Host "Setting up RustScan..."
$rustScanUrl = "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan-2.3.0-x86_64-win-gnu.zip"
$rustScanZip = Join-Path $toolsDir "rustscan.zip"
$rustScanDir = Join-Path $toolsDir "rustscan"
if (Start-Download -name "RustScan" -url $rustScanUrl -outputFile $rustScanZip) {
    Extract-Tool -name "RustScan" -zipFile $rustScanZip -extractDir $rustScanDir
    # Find and move rustscan.exe to the correct location
    $rustScanExe = Get-ChildItem -Path $rustScanDir -Recurse -Filter "rustscan.exe" | Select-Object -First 1
    if ($rustScanExe) {
        Move-Item $rustScanExe.FullName (Join-Path $rustScanDir "rustscan.exe") -Force
    }
}

# Download and extract John the Ripper
Write-Host "Setting up John the Ripper..."
$johnUrl = "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip"
$johnZip = Join-Path $toolsDir "john.zip"
if (Start-Download -name "John the Ripper" -url $johnUrl -outputFile $johnZip) {
    Extract-Tool -name "John the Ripper" -zipFile $johnZip
}

# Download and install Python
Write-Host "Installing Python..."
$pythonUrl = "https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe"
$pythonInstaller = Join-Path $toolsDir "python.exe"
if (Start-Download -name "Python" -url $pythonUrl -outputFile $pythonInstaller) {
    Start-Process -Wait -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -NoNewWindow
    Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue
}

# Download SecLists wordlist
Write-Host "Downloading SecLists wordlist..."
$secListsDir = Join-Path $toolsDir "SecLists\Discovery\Web-Content"
New-Item -ItemType Directory -Force -Path $secListsDir | Out-Null
$wordlistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
$wordlistPath = Join-Path $secListsDir "raft-medium-directories.txt"
Start-Download -name "SecLists wordlist" -url $wordlistUrl -outputFile $wordlistPath

# Download and install Metasploit
Write-Host "Installing Metasploit..."
$metasploitUrl = "https://windows.metasploit.com/metasploitframework-latest.msi"
$metasploitInstaller = Join-Path $toolsDir "metasploit.msi"
if (Start-Download -name "Metasploit" -url $metasploitUrl -outputFile $metasploitInstaller) {
    Start-Process -Wait -FilePath "msiexec.exe" -ArgumentList "/i `"$metasploitInstaller`" /qn" -NoNewWindow
    Remove-Item $metasploitInstaller -Force -ErrorAction SilentlyContinue
}

# Update PATH environment variable
Write-Host "Updating PATH environment variable..."
try {
    $pathsToAdd = @(
        $feroxDir,
        $rustScanDir,
        (Join-Path $toolsDir "john\john-1.9.0-jumbo-1-win64\run")
    )
    
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = ($currentPath.Split(';') + $pathsToAdd | Select-Object -Unique) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    $env:Path = $newPath
    Write-Host "Successfully updated PATH"
} catch {
    $errorMessage = $_.Exception.Message
    Write-Host "Error updating PATH: $errorMessage"
}

# Show final status
Write-Host "`nInstallation complete. Checking installed tools..."
Get-ChildItem $toolsDir -Directory | Format-Table Name

Write-Host "Testing tools..."
if (Test-Path (Join-Path $feroxDir "feroxbuster.exe")) {
    Write-Host "FeroxBuster found"
}
if (Test-Path (Join-Path $rustScanDir "rustscan.exe")) {
    Write-Host "RustScan found"
}

Write-Host "Installing Windows Terminal..."
try {
    # Create a temporary directory for installers
    $tempDir = Join-Path $toolsDir "temp_installers"
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

    # Download dependencies first
    $dependencies = @(
        @{
            name = "VCLibs"
            url = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
            file = "vclibs.appx"
        },
        @{
            name = "UI Xaml 2.8"
            url = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6"
            file = "microsoft.ui.xaml.2.8.zip"
        },
        @{
            name = "Windows Terminal"
            url = "https://github.com/microsoft/terminal/releases/download/v1.18.3181.0/Microsoft.WindowsTerminal_1.18.3181.0_8wekyb3d8bbwe.msixbundle"
            file = "terminal.msixbundle"
        }
    )

    foreach ($dep in $dependencies) {
        $outputFile = Join-Path $tempDir $dep.file
        Start-Download -name $dep.name -url $dep.url -outputFile $outputFile
    }

    # Extract and prepare UI Xaml
    $xamlZip = Join-Path $tempDir "microsoft.ui.xaml.2.8.zip"
    $xamlExtractPath = Join-Path $tempDir "xaml"
    Expand-Archive -Path $xamlZip -DestinationPath $xamlExtractPath -Force

    # Install packages in correct order
    Write-Host "Installing VCLibs..."
    Add-AppxPackage -Path (Join-Path $tempDir "vclibs.appx")

    Write-Host "Installing UI Xaml 2.8..."
    Add-AppxPackage -Path "$xamlExtractPath\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.8.appx"

    Write-Host "Installing Windows Terminal..."
    Add-AppxPackage -Path (Join-Path $tempDir "terminal.msixbundle")

    # Clean up
    Remove-Item $tempDir -Recurse -Force

    Write-Host "Windows Terminal installed successfully"

    # Create custom Windows Terminal settings
    $settingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState"
    New-Item -ItemType Directory -Force -Path $settingsPath | Out-Null
    
    $settings = @{
        '$schema' = "https://aka.ms/terminal-profiles-schema"
        defaultProfile = "{61c54bbd-c2c6-5271-96e7-009a87ff44bf}"
        profiles = @{
            defaults = @{
                font = @{
                    face = "Cascadia Code"
                    size = 12
                }
                opacity = 95
                useAcrylic = $true
                scrollbarState = "visible"
                padding = "8,8,8,8"
            }
            list = @(
                @{
                    guid = "{61c54bbd-c2c6-5271-96e7-009a87ff44bf}"
                    name = "Windows PowerShell"
                    commandline = "powershell.exe"
                    hidden = $false
                    colorScheme = "One Half Dark"
                    startingDirectory = "C:\SecurityTools"
                }
            )
        }
        schemes = @(
            @{
                name = "One Half Dark"
                background = "#282C34"
                foreground = "#DCDFE4"
                black = "#282C34"
                red = "#E06C75"
                green = "#98C379"
                yellow = "#E5C07B"
                blue = "#61AFEF"
                purple = "#C678DD"
                cyan = "#56B6C2"
                white = "#DCDFE4"
                brightBlack = "#5A6374"
                brightRed = "#E06C75"
                brightGreen = "#98C379"
                brightYellow = "#E5C07B"
                brightBlue = "#61AFEF"
                brightPurple = "#C678DD"
                brightCyan = "#56B6C2"
                brightWhite = "#DCDFE4"
            }
        )
    }
    
    $settings | ConvertTo-Json -Depth 10 | Out-File (Join-Path $settingsPath "settings.json") -Encoding UTF8

    # Create a desktop shortcut
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Terminal.lnk")
    $Shortcut.TargetPath = "wt.exe"
    $Shortcut.Save()

    Write-Host "Windows Terminal setup complete"
} catch {
    $errorMessage = $_.Exception.Message
    Write-Host "Error installing Windows Terminal: $errorMessage"
    Write-Host "Continuing with default terminal..."
}

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator!"
    Exit
}

# Path to the registry key for app theme
$RegKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"

# Set dark theme for apps
Set-ItemProperty -Path $RegKeyPath -Name "AppsUseLightTheme" -Value 0

# Set dark theme for Windows
Set-ItemProperty -Path $RegKeyPath -Name "SystemUsesLightTheme" -Value 0

# Optional: Set dark theme for Office (if installed)
$OfficeRegPath = "HKCU:\Software\Microsoft\Office\16.0\Common"
if (Test-Path $OfficeRegPath) {
    Set-ItemProperty -Path $OfficeRegPath -Name "UI Theme" -Value 4
}

Write-Host "Restarting Explorer to apply changes..."

# Stop Explorer process
Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue

# Wait a moment for the process to fully stop
Start-Sleep -Seconds 2

# Start Explorer again
Start-Process "explorer.exe"

Write-Host "Dark theme has been enabled and Explorer has been restarted. Changes should now be visible."
Write-Host "Note: Some applications may need to be restarted to show the dark theme."


# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator!"
    Exit
}

# Create a temporary directory
$tempDirectory = "$env:TEMP\BraveInstall"
New-Item -ItemType Directory -Force -Path $tempDirectory | Out-Null

# Download URL for Brave Browser
$braveUrl = "https://brave-browser-downloads.s3.brave.com/latest/brave_installer-x64.exe"
$installerPath = "$tempDirectory\brave_installer.exe"

try {
    Write-Host "Downloading Brave Browser..."
    
    # Download the installer
    Invoke-WebRequest -Uri $braveUrl -OutFile $installerPath
    
    if (Test-Path $installerPath) {
        Write-Host "Installing Brave Browser..."
        
        # Install Brave silently
        Start-Process -FilePath $installerPath -ArgumentList "--silent","--system-level" -Wait
        
        Write-Host "Brave Browser has been installed successfully!"
    } else {
        Write-Error "Failed to download Brave Browser installer."
    }
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    # Clean up
    if (Test-Path $tempDirectory) {
        Remove-Item -Path $tempDirectory -Recurse -Force
        Write-Host "Cleaned up temporary files."
    }
}

$BackgroundUrl = "https://github.com/pentestfunctions/hypervarch/blob/main/scripts/resources/background.png?raw=true"
$BackgroundPath = "C:\SecurityTools\background.png"
Start-Download -name "Background" -url $BackgroundUrl -outputFile $BackgroundPath

$setwallpapersrc = @"
using System.Runtime.InteropServices;

public class Wallpaper
{
  public const int SetDesktopWallpaper = 20;
  public const int UpdateIniFile = 0x01;
  public const int SendWinIniChange = 0x02;
  [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
  private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
  public static void SetWallpaper(string path)
  {
    SystemParametersInfo(SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange);
  }
}
"@
Add-Type -TypeDefinition $setwallpapersrc

[Wallpaper]::SetWallpaper($BackgroundPath)

# Check if Brave is now installed
$bravePath = "${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\brave.exe"
if (Test-Path $bravePath) {
    Write-Host "Installation verified successfully."
} else {
    Write-Warning "Installation may have failed. Please check manually."
}

# Set TLS 1.2 for download
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define variables
$downloadUrl = "https://swupdate.openvpn.net/downloads/connect/openvpn-connect-3.5.1.3946_signed.msi"
$installerPath = "$env:TEMP\openvpn-connect.msi"

try {
    # Download the installer
    Write-Host "Downloading OpenVPN Connect..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
    
    # Install silently
    Write-Host "Installing OpenVPN Connect..."
    Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn" -Wait
    
    # Clean up
    Remove-Item -Path $installerPath -Force
    Write-Host "Installation completed successfully"
}
catch {
    Write-Host "An error occurred: $_"
}

# Set variables
$installPath = "C:\Windows\System32"
$ncUrl = "https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip"
$downloadPath = "$env:TEMP\nc.zip"
$extractPath = "$env:TEMP\nc"

try {
    # Download netcat zip
    Write-Host "Downloading Netcat..."
    Invoke-WebRequest -Uri $ncUrl -OutFile $downloadPath
    
    # Create extraction directory if it doesn't exist
    if (-not (Test-Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath | Out-Null
    }
    
    # Extract the zip
    Write-Host "Extracting Netcat..."
    Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
    
    # Copy nc.exe to System32 (this will make it available system-wide)
    Write-Host "Installing Netcat..."
    Copy-Item "$extractPath\nc.exe" -Destination $installPath -Force
    
    # Clean up
    Write-Host "Cleaning up..."
    Remove-Item $downloadPath -Force
    Remove-Item $extractPath -Recurse -Force
    
    # Verify installation
    if (Test-Path "$installPath\nc.exe") {
        Write-Host "Netcat installed successfully! You can now use 'nc' from any command prompt."
    } else {
        Write-Host "Installation may have failed. Please check if nc.exe exists in $installPath"
    }
}
catch {
    Write-Host "An error occurred: $_"
}


# Hardcoded installation path and force flag
$InstallPath = "$env:ProgramFiles\Ruby33-x64"
$Force = $true  # Set to $true if you want to force installation, or $false otherwise

# Function to write to log file and console
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "$timestamp`: $Message"
}


# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "Please run as administrator"
}

try {
    # Install Ruby if not present or if Force is specified
    if($Force -or -not (Test-Path "$InstallPath\bin\ruby.exe")) {
        Write-Log "Installing Ruby..."
        $rubyInstaller = "https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-3.3.6-2/rubyinstaller-devkit-3.3.6-2-x64.exe"
        $installerPath = Join-Path $env:TEMP "rubyinstaller-devkit.exe"
        
        Invoke-WebRequest -Uri $rubyInstaller -OutFile $installerPath -UseBasicParsing
        Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /TYPE=full /DIR=`"$InstallPath`"" -Wait -NoNewWindow
        
        Write-Log "Installing Ruby DevKit..."
        $ridkPath = Join-Path $InstallPath "bin\ridk.cmd"
        $env:RIDK_INSTALL_QUIET = 1
        Start-Process -FilePath $ridkPath -ArgumentList "install 1 2 3" -Wait -NoNewWindow
    }

    # Create WPScan installation script
    $wpscanScript = @"
`$env:Path = "$InstallPath\bin;`$env:Path"
Write-Output "Installing WPScan..."
& "$InstallPath\bin\gem.cmd" install wpscan --no-document
if (`$LASTEXITCODE -eq 0) {
    Write-Output "WPScan installed successfully"
    & "$InstallPath\bin\wpscan.bat" --version
}
"@

    $scriptPath = Join-Path $env:TEMP "install_wpscan.ps1"
    $wpscanScript | Set-Content -Path $scriptPath
    
    Write-Log "Installing WPScan..."
    $process = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Wait -NoNewWindow -PassThru
    
    if($process.ExitCode -ne 0) {
        throw "WPScan installation failed"
    }

    Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
    Write-Log "Installation completed successfully"
}
catch {
    Write-Log "Installation failed: $_"
    throw
}

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Please run as administrator"
    return
}

$curlUrl = "https://curl.se/windows/dl-8.11.0_1/curl-8.11.0_1-win64-mingw.zip"
$tempPath = Join-Path $env:TEMP "curl_temp"

# Define all possible paths where Ruby might look for DLLs
$targetPaths = @(
    "C:\Program Files\Ruby33-x64\bin",
    "C:\Program Files\Ruby33-x64\lib",
    "C:\Program Files\Ruby33-x64\lib\ruby\3.3.0\x64-mingw-ucrt",
    "C:\Program Files\Ruby33-x64\lib\ruby\gems\3.3.0\gems\ffi-1.17.0-x64-mingw-ucrt\lib\ffi",
    "C:\Windows\System32"
)

try {
    # Create temp directory
    Write-Output "Creating temporary directory..."
    New-Item -ItemType Directory -Force -Path $tempPath | Out-Null

    # Create target directories if they don't exist
    foreach ($path in $targetPaths) {
        if (-not (Test-Path $path)) {
            Write-Output "Creating directory: $path"
            New-Item -ItemType Directory -Force -Path $path | Out-Null
        }
    }

    # Download curl package
    Write-Output "Downloading curl package..."
    $zipPath = Join-Path $tempPath "curl.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $curlUrl -OutFile $zipPath -UseBasicParsing

    # Extract package
    Write-Output "Extracting curl package..."
    Expand-Archive -Path $zipPath -DestinationPath $tempPath -Force

    # Copy and rename DLLs
    Write-Output "Copying and renaming DLLs..."
    $curlBinPath = Get-ChildItem -Path $tempPath -Filter "bin" -Recurse | Select-Object -First 1
    
    if ($curlBinPath) {
        # Find the libcurl DLL
        $libcurlDll = Get-ChildItem -Path $curlBinPath.FullName -Filter "libcurl*.dll" | Select-Object -First 1
        
        if ($libcurlDll) {
            foreach ($targetPath in $targetPaths) {
                Write-Output "`nCopying to $targetPath..."
                
                # Copy with exact names that Ruby is looking for
                $targetNames = @(
                    "libcurl.dll",
                    "curl.dll",
                    "libcurl.so.4",
                    "libcurl.so.4.dll"
                )

                foreach ($targetName in $targetNames) {
                    try {
                        Copy-Item $libcurlDll.FullName -Destination (Join-Path $targetPath $targetName) -Force
                        Write-Output "Created $targetName"
                    } catch {
                        Write-Output "Failed to copy to $targetPath : $_"
                    }
                }

                # Also copy support DLLs
                $supportDlls = @(
                    "zlib*.dll",
                    "libssl*.dll",
                    "libcrypto*.dll",
                    "libssh2*.dll"
                )

                foreach ($dll in $supportDlls) {
                    Get-ChildItem -Path $curlBinPath.FullName -Filter $dll -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            Copy-Item $_.FullName -Destination $targetPath -Force
                            Write-Output "Copied support DLL: $($_.Name)"
                        } catch {
                            Write-Output "Failed to copy support DLL to $targetPath : $_"
                        }
                    }
                }
            }
        } else {
            Write-Output "Could not find libcurl DLL in package"
        }
    } else {
        Write-Output "Could not find bin directory in curl package"
    }

    # Clean up
    Remove-Item -Path $tempPath -Recurse -Force

    Write-Output "`nVerifying installations..."
    foreach ($path in $targetPaths) {
        Write-Output "`nDLLs in $path :"
        Get-ChildItem "$path\*.dll" -ErrorAction SilentlyContinue | Select-Object Name
    }

    Write-Output "`nDependencies installation completed."
    Write-Output "You can now run wpscan."

} catch {
    Write-Output "An error occurred: $_"
    Write-Output "Error details: $($_.Exception.Message)"
}

Write-Host "`nPlease restart your terminal for PATH changes to take effect."
