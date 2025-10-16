<#
.SYNOPSIS
    用于构建精简版 Windows 11 镜像的脚本. 修改部分贴合自用.

.DESCRIPTION
    此脚本旨在自动化构建精简版 Windows 11 镜像,类似于 tiny10.
    我的主要目标是仅使用 Microsoft 实用程序(如 DISM),不使用来自外部来源的实用程序.
    包含的唯一可执行文件是 oscdimg.exe,它由 Windows ADK 提供,用于创建可启动的 ISO 镜像.

.PARAMETER ISO
    分配给已挂载 ISO 的驱动器号(例如：E)

.PARAMETER SCRATCH
    所需暂存磁盘的驱动器号(例如：D)

.EXAMPLE
    .\dogmaker.ps1 E D
    .\dogmaker.ps1 -ISO E -SCRATCH D
    .\dogmaker.ps1 -SCRATCH D -ISO E
    .\dogmaker.ps1

    *如果使用位置参数,第一个必须是已挂载的 ISO 驱动器号,第二个是暂存驱动器.
    建议使用完整的命名参数(例如："-ISO"),因为可以按任意顺序放置.

.NOTES
    作者: ntdevlabs
    日期: 09-07-25
#>

#---------[ 参数 ]---------#
param (
    [ValidatePattern('^[c-zC-Z]$')][string]$ISO,
    [ValidatePattern('^[c-zC-Z]$')][string]$SCRATCH
)

if (-not $SCRATCH) {
    $ScratchDisk = $PSScriptRoot -replace '[\\]+$', ''
} else {
    $ScratchDisk = $SCRATCH + ":"
}

#---------[ 函数 ]---------#
function Set-RegistryValue {
    param (
        [string]$path,
        [string]$name,
        [string]$type,
        [string]$value
    )
    try {
        & 'reg' 'add' $path '/v' $name '/t' $type '/d' $value '/f' | Out-Null
        Write-Output "设置注册表值: $path\$name"
    } catch {
        Write-Output "设置注册表值时出错: $_"
    }
}

function Remove-RegistryValue {
    param (
		[string]$path
	)
	try {
		& 'reg' 'delete' $path '/f' | Out-Null
		Write-Output "已删除注册表值: $path"
	} catch {
		Write-Output "删除注册表值时出错: $_"
	}
}

#---------[ 执行 ]---------#
# 检查 PowerShell 执行是否受限
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Output "您当前的 PowerShell 执行策略设置为 Restricted,这会阻止脚本运行.是否要将其更改为 RemoteSigned?(yes/no)"
    $response = Read-Host
    if ($response -eq 'yes') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    } else {
        Write-Output "不更改执行策略无法运行脚本.正在退出..."
        exit
    }
}

# 检查并在需要时以管理员身份运行脚本
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole))
{
    Write-Output "正在新窗口中以管理员身份重新启动 dog 镜像创建器,您可以关闭此窗口."
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

if (-not (Test-Path -Path "$PSScriptRoot/autounattend.xml")) {
    Invoke-RestMethod "https://raw.githubusercontent.com/Maskeva/dogbuilder/refs/heads/main/autounattend.xml" -OutFile "$PSScriptRoot/autounattend.xml"
}

# 开始记录并准备窗口
Start-Transcript -Path "$PSScriptRoot\dog_$(get-date -f yyyyMMdd_HHmms).log"

$Host.UI.RawUI.WindowTitle = "dog 镜像创建器"
Clear-Host
Write-Output "欢迎使用 dog 镜像创建器！版本: 09-07-25"

$hostArchitecture = $Env:PROCESSOR_ARCHITECTURE
New-Item -ItemType Directory -Force -Path "$ScratchDisk\dog\sources" | Out-Null
do {
    if (-not $ISO) {
        $DriveLetter = Read-Host "Please enter the drive letter of your Windows 11 image"
    } else {
        $DriveLetter = $ISO
    }
    if ($DriveLetter -match '^[c-zC-Z]$') {
        $DriveLetter = $DriveLetter + ":"
        Write-Output "驱动器号设置为 $DriveLetter"
    } else {
        Write-Output "Invalid drive letter. Please enter a letter between C and Z."
    }
} while ($DriveLetter -notmatch '^[c-zC-Z]:$')

if ((Test-Path "$DriveLetter\sources\boot.wim") -eq $false -or (Test-Path "$DriveLetter\sources\install.wim") -eq $false) {
    if ((Test-Path "$DriveLetter\sources\install.esd") -eq $true) {
        Write-Output "找到 install.esd,正在转换为 install.wim..."
        Get-WindowsImage -ImagePath $DriveLetter\sources\install.esd
        $index = Read-Host "请输入镜像索引"
        Write-Output ' '
        Write-Output '正在将 install.esd 转换为 install.wim.这可能需要一段时间...'
        Export-WindowsImage -SourceImagePath $DriveLetter\sources\install.esd -SourceIndex $index -DestinationImagePath $ScratchDisk\dog\sources\install.wim -Compressiontype Maximum -CheckIntegrity
    } else {
        Write-Output "在指定的驱动器号中找不到 Windows 操作系统安装文件.."
        Write-Output "请输入正确的 DVD 驱动器号.."
        exit
    }
}

Write-Output "正在复制 Windows 镜像..."
Copy-Item -Path "$DriveLetter\*" -Destination "$ScratchDisk\dog" -Recurse -Force | Out-Null
Set-ItemProperty -Path "$ScratchDisk\dog\sources\install.esd" -Name IsReadOnly -Value $false > $null 2>&1
Remove-Item "$ScratchDisk\dog\sources\install.esd" > $null 2>&1
Write-Output "复制完成！"
Start-Sleep -Seconds 2
Clear-Host
Write-Output "正在获取镜像信息:"
$ImagesIndex = (Get-WindowsImage -ImagePath $ScratchDisk\dog\sources\install.wim).ImageIndex
while ($ImagesIndex -notcontains $index) {
    Get-WindowsImage -ImagePath $ScratchDisk\dog\sources\install.wim
    $index = Read-Host "请输入镜像索引"
}
Write-Output "正在挂载 Windows 镜像.这可能需要一段时间."
$wimFilePath = "$ScratchDisk\dog\sources\install.wim"
& takeown "/F" $wimFilePath
& icacls $wimFilePath "/grant" "$($adminGroup.Value):(F)"
try {
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction Stop
} catch {
    # 此块将捕获错误并抑制它.
	Write-Error "$wimFilePath 未找到"
}
New-Item -ItemType Directory -Force -Path "$ScratchDisk\scratchdir" > $null
Mount-WindowsImage -ImagePath $ScratchDisk\dog\sources\install.wim -Index $index -Path $ScratchDisk\scratchdir

$imageIntl = & dism /English /Get-Intl "/Image:$($ScratchDisk)\scratchdir"
$languageLine = $imageIntl -split '\n' | Where-Object { $_ -match 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})' }

if ($languageLine) {
    $languageCode = $Matches[1]
    Write-Output "默认系统 UI 语言代码: $languageCode"
} else {
    Write-Output "未找到默认系统 UI 语言代码."
}

$imageInfo = & 'dism' '/English' '/Get-WimInfo' "/wimFile:$($ScratchDisk)\dog\sources\install.wim" "/index:$index"
$lines = $imageInfo -split '\r?\n'

foreach ($line in $lines) {
    if ($line -like '*Architecture : *') {
        $architecture = $line -replace 'Architecture : ',''
        # 如果架构是 x64,则替换为 amd64
        if ($architecture -eq 'x64') {
            $architecture = 'amd64'
        }
        Write-Output "架构: $architecture"
        break
    }
}

if (-not $architecture) {
    Write-Output "未找到架构信息."
}

Write-Output "挂载完成！正在执行应用程序移除..."

$packages = & 'dism' '/English' "/image:$($ScratchDisk)\scratchdir" '/Get-ProvisionedAppxPackages' |
    ForEach-Object {
        if ($_ -match 'PackageName : (.*)') {
            $matches[1]
        }
    }

$packagePrefixes = 'AppUp.IntelManagementandSecurityStatus',
'Clipchamp.Clipchamp', 
'DolbyLaboratories.DolbyAccess',
'DolbyLaboratories.DolbyDigitalPlusDecoderOEM',
'Microsoft.BingNews',
'Microsoft.BingSearch',
'Microsoft.BingWeather',
'Microsoft.Copilot',
'Microsoft.Windows.CrossDevice',
'Microsoft.GamingApp',
'Microsoft.GetHelp',
'Microsoft.Getstarted',
'Microsoft.Microsoft3DViewer',
'Microsoft.MicrosoftOfficeHub',
'Microsoft.MicrosoftSolitaireCollection',
'Microsoft.MicrosoftStickyNotes',
'Microsoft.MixedReality.Portal',
'Microsoft.MSPaint',
'Microsoft.Office.OneNote',
'Microsoft.OfficePushNotificationUtility',
'Microsoft.OutlookForWindows',
'Microsoft.Paint',
'Microsoft.People',
'Microsoft.PowerAutomateDesktop',
'Microsoft.SkypeApp',
'Microsoft.StartExperiencesApp',
'Microsoft.Todos',
'Microsoft.Wallet',
'Microsoft.Windows.DevHome',
'Microsoft.Windows.Copilot',
'Microsoft.Windows.Teams',
'Microsoft.WindowsAlarms',
'Microsoft.WindowsCamera',
'microsoft.windowscommunicationsapps',
'Microsoft.WindowsFeedbackHub',
'Microsoft.WindowsMaps',
'Microsoft.WindowsSoundRecorder',
'Microsoft.WindowsTerminal',
'Microsoft.Xbox.TCUI',
'Microsoft.XboxApp',
'Microsoft.XboxGameOverlay',
'Microsoft.XboxGamingOverlay',
'Microsoft.XboxIdentityProvider',
'Microsoft.XboxSpeechToTextOverlay',
'Microsoft.YourPhone',
'Microsoft.ZuneMusic',
'Microsoft.ZuneVideo',
'MicrosoftCorporationII.MicrosoftFamily',
'MicrosoftCorporationII.QuickAssist',
'MSTeams',
'MicrosoftTeams', 
'Microsoft.WindowsTerminal',
'Microsoft.549981C3F5F10',
'Microsoft.ScreenSketch',
'Microsoft.StorePurchaseApp',
'Microsoft.Windows.Photos',
'MicrosoftWindows.Client.WebExperience'



$packagesToRemove = $packages | Where-Object {
    $packageName = $_
    $packagePrefixes -contains ($packagePrefixes | Where-Object { $packageName -like "*$_*" })
}
foreach ($package in $packagesToRemove) {
    & 'dism' '/English' "/image:$($ScratchDisk)\scratchdir" '/Remove-ProvisionedAppxPackage' "/PackageName:$package"
}

Write-Output "正在移除 Edge:"
Remove-Item -Path "$ScratchDisk\scratchdir\Program Files (x86)\Microsoft\Edge" -Recurse -Force | Out-Null
Remove-Item -Path "$ScratchDisk\scratchdir\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force | Out-Null
Remove-Item -Path "$ScratchDisk\scratchdir\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force | Out-Null
& 'takeown' '/f' "$ScratchDisk\scratchdir\Windows\System32\Microsoft-Edge-Webview" '/r' | Out-Null
& 'icacls' "$ScratchDisk\scratchdir\Windows\System32\Microsoft-Edge-Webview" '/grant' "$($adminGroup.Value):(F)" '/T' '/C' | Out-Null
Remove-Item -Path "$ScratchDisk\scratchdir\Windows\System32\Microsoft-Edge-Webview" -Recurse -Force | Out-Null
Write-Output "正在移除 OneDrive:"
& 'takeown' '/f' "$ScratchDisk\scratchdir\Windows\System32\OneDriveSetup.exe" | Out-Null
& 'icacls' "$ScratchDisk\scratchdir\Windows\System32\OneDriveSetup.exe" '/grant' "$($adminGroup.Value):(F)" '/T' '/C' | Out-Null
Remove-Item -Path "$ScratchDisk\scratchdir\Windows\System32\OneDriveSetup.exe" -Force | Out-Null

# 删除 WinSxS 文件夹下的 OneDrive 相关目录
Write-Output "正在移除 WinSxS 中的 OneDrive 组件..."
$oneDriveSxsPaths = Get-ChildItem -Path "$ScratchDisk\scratchdir\Windows\WinSxS" -Directory | Where-Object { $_.Name -like "*OneDrive*" }
foreach ($sxsPath in $oneDriveSxsPaths) {
    try {
        & 'takeown' '/f' $sxsPath.FullName '/r' '/d y' | Out-Null
        & 'icacls' $sxsPath.FullName '/grant' "$($adminGroup.Value):(F)" '/T' '/C' | Out-Null
        Remove-Item -Path $sxsPath.FullName -Recurse -Force -ErrorAction Stop
        Write-Output "已移除 OneDrive SxS 组件: $($sxsPath.Name)"
    } catch {
        Write-Output "移除 OneDrive SxS 组件失败: $($sxsPath.Name) - $_"
    }
}

Write-Output "移除完成！"
Start-Sleep -Seconds 2
Clear-Host
Write-Output "正在加载注册表..."
reg load HKLM\zCOMPONENTS $ScratchDisk\scratchdir\Windows\System32\config\COMPONENTS | Out-Null
reg load HKLM\zDEFAULT $ScratchDisk\scratchdir\Windows\System32\config\default | Out-Null
reg load HKLM\zNTUSER $ScratchDisk\scratchdir\Users\Default\ntuser.dat | Out-Null
reg load HKLM\zSOFTWARE $ScratchDisk\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
reg load HKLM\zSYSTEM $ScratchDisk\scratchdir\Windows\System32\config\SYSTEM | Out-Null
Write-Output "正在禁用赞助应用:"
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'OemPreInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'ContentDeliveryAllowed' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' 'ConfigureStartPins' 'REG_SZ' '{"pinnedList": [{}]}'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'FeatureManagementEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEverEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContentEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' 'DisablePushToInstall' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' 'DontOfferThroughWUAU' 'REG_DWORD' '1'
Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 'REG_DWORD' '1'
Write-Output "在 OOBE 上启用本地账户:"
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'BypassNRO' 'REG_DWORD' '1'
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$ScratchDisk\scratchdir\Windows\System32\Sysprep\autounattend.xml" -Force | Out-Null

Write-Output "正在禁用保留存储:"
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' 'ShippedWithReserves' 'REG_DWORD' '0'
Write-Output "正在禁用 BitLocker 设备加密"
Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' 'PreventDeviceEncryption' 'REG_DWORD' '1'
Write-Output "正在禁用聊天图标:"
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' 'ChatIcon' 'REG_DWORD' '3'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' 'REG_DWORD' '0'
Write-Output "正在移除 Edge 相关注册表项"
Remove-RegistryValue "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
Remove-RegistryValue "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"
Write-Output "正在禁用 OneDrive 文件夹备份"
Set-RegistryValue "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "REG_DWORD" "1"
Write-Output "正在禁用遥测:"
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' 'HasAccepted' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' 'Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' 'AcceptedPrivacyPolicy' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' 'Start' 'REG_DWORD' '4'
## 阻止安装 DevHome 和 Outlook
Write-Output "正在阻止安装 DevHome 和 Outlook:"
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' 'workCompleted' 'REG_DWORD' '1'
Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'
Write-Output "正在禁用 Copilot"
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 'REG_DWORD' '1'
Write-Output "正在阻止安装 Teams:"
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' 'DisableInstallation' 'REG_DWORD' '1'
Write-Output "正在阻止安装 New Outlook":
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' 'PreventRun' 'REG_DWORD' '1'

Write-Host "正在删除计划任务定义文件..."
$tasksPath = "$ScratchDisk\scratchdir\Windows\System32\Tasks"

# 应用程序兼容性评估器
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -Force -ErrorAction SilentlyContinue

# 客户体验改善计划(移除整个文件夹及其中的所有任务)
Remove-Item -Path "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program" -Recurse -Force -ErrorAction SilentlyContinue

# 程序数据更新器
Remove-Item -Path "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater" -Force -ErrorAction SilentlyContinue

# Chkdsk 代理
Remove-Item -Path "$tasksPath\Microsoft\Windows\Chkdsk\Proxy" -Force -ErrorAction SilentlyContinue

# Windows 错误报告(QueueReporting)
Remove-Item -Path "$tasksPath\Microsoft\Windows\Windows Error Reporting\QueueReporting" -Force -ErrorAction SilentlyContinue
Write-Host "任务文件已删除."
Write-Host "正在卸载注册表..."
reg unload HKLM\zCOMPONENTS | Out-Null
reg unload HKLM\zDEFAULT | Out-Null
reg unload HKLM\zNTUSER | Out-Null
reg unload HKLM\zSOFTWARE | Out-Null
reg unload HKLM\zSYSTEM | Out-Null
Write-Output "正在清理镜像..."
dism.exe /Image:$ScratchDisk\scratchdir /Cleanup-Image /StartComponentCleanup /ResetBase
Write-Output "清理完成."
Write-Output ' '
Write-Output "正在卸载镜像..."
Dismount-WindowsImage -Path $ScratchDisk\scratchdir -Save
Write-Host "正在导出镜像..."
Dism.exe /Export-Image /SourceImageFile:"$ScratchDisk\dog\sources\install.wim" /SourceIndex:$index /DestinationImageFile:"$ScratchDisk\dog\sources\install2.wim" /Compress:recovery
Remove-Item -Path "$ScratchDisk\dog\sources\install.wim" -Force | Out-Null
Rename-Item -Path "$ScratchDisk\dog\sources\install2.wim" -NewName "install.wim" | Out-Null
Write-Output "Windows 镜像已完成.继续处理 boot.wim."
Start-Sleep -Seconds 2
Clear-Host

Write-Output "dog 镜像现已完成.正在继续制作 ISO..."
Write-Output "正在复制用于在 OOBE 上绕过 Microsoft 账户的无人值守文件..."
Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$ScratchDisk\dog\autounattend.xml" -Force | Out-Null
Write-Output "正在创建 ISO 镜像..."
$ADKDepTools = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$hostarchitecture\Oscdimg"
$localOSCDIMGPath = "$PSScriptRoot\oscdimg.exe"

if ([System.IO.Directory]::Exists($ADKDepTools)) {
    Write-Output "将使用系统 ADK 中的 oscdimg.exe."
    $OSCDIMG = "$ADKDepTools\oscdimg.exe"
} else {
    Write-Output "未找到 ADK 文件夹.将使用捆绑的 oscdimg.exe."
    $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"

    if (-not (Test-Path -Path $localOSCDIMGPath)) {
        Write-Output "正在下载 oscdimg.exe..."
        Invoke-WebRequest -Uri $url -OutFile $localOSCDIMGPath

        if (Test-Path $localOSCDIMGPath) {
            Write-Output "oscdimg.exe 下载成功."
        } else {
            Write-Error "下载 oscdimg.exe 失败."
            exit 1
        }
    } else {
        Write-Output "oscdimg.exe 已本地存在."
    }

    $OSCDIMG = $localOSCDIMGPath
}

& "$OSCDIMG" '-m' '-o' '-u2' '-udfver102' "-bootdata:2#p0,e,b$ScratchDisk\dog\boot\etfsboot.com#pEF,e,b$ScratchDisk\dog\efi\microsoft\boot\efisys.bin" "$ScratchDisk\dog" "$PSScriptRoot\dog.iso"

# 收尾工作
Write-Output "创建完成！按任意键退出脚本..."
Read-Host "按回车键继续"
Write-Output "正在执行清理..."
Remove-Item -Path "$ScratchDisk\dog" -Recurse -Force | Out-Null
Remove-Item -Path "$ScratchDisk\scratchdir" -Recurse -Force | Out-Null
Write-Output "正在弹出 ISO 驱动器"
Get-Volume -DriveLetter $DriveLetter[0] | Get-DiskImage | Dismount-DiskImage
Write-Output "ISO 驱动器已弹出"
Write-Output "正在移除 oscdimg.exe..."
Remove-Item -Path "$PSScriptRoot\oscdimg.exe" -Force -ErrorAction SilentlyContinue
Write-Output "正在移除 autounattend.xml..."
Remove-Item -Path "$PSScriptRoot\autounattend.xml" -Force -ErrorAction SilentlyContinue

Write-Output "清理检查:"
if (Test-Path -Path "$ScratchDisk\dog") {
    Write-Output "dog 文件夹仍然存在.正在尝试再次移除..."
    Remove-Item -Path "$ScratchDisk\dog" -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -Path "$ScratchDisk\dog") {
        Write-Output "移除 dog 文件夹失败."
    } else {
        Write-Output "dog 文件夹已成功移除."
    }
} else {
    Write-Output "dog 文件夹不存在.无需操作."
}
if (Test-Path -Path "$ScratchDisk\scratchdir") {
    Write-Output "scratchdir 文件夹仍然存在.正在尝试再次移除..."
    Remove-Item -Path "$ScratchDisk\scratchdir" -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -Path "$ScratchDisk\scratchdir") {
        Write-Output "移除 scratchdir 文件夹失败."
    } else {
        Write-Output "scratchdir 文件夹已成功移除."
    }
} else {
    Write-Output "scratchdir 文件夹不存在.无需操作."
}
if (Test-Path -Path "$PSScriptRoot\oscdimg.exe") {
    Write-Output "oscdimg.exe 仍然存在.正在尝试再次移除..."
    Remove-Item -Path "$PSScriptRoot\oscdimg.exe" -Force -ErrorAction SilentlyContinue
    if (Test-Path -Path "$PSScriptRoot\oscdimg.exe") {
        Write-Output "移除 oscdimg.exe 失败."
    } else {
        Write-Output "oscdimg.exe 已成功移除."
    }
} else {
    Write-Output "oscdimg.exe 不存在.无需操作."
}
if (Test-Path -Path "$PSScriptRoot\autounattend.xml") {
    Write-Output "autounattend.xml 仍然存在.正在尝试再次移除..."
    Remove-Item -Path "$PSScriptRoot\autounattend.xml" -Force -ErrorAction SilentlyContinue
    if (Test-Path -Path "$PSScriptRoot\autounattend.xml") {
        Write-Output "移除 autounattend.xml 失败."
    } else {
        Write-Output "autounattend.xml 已成功移除."
    }
} else {
    Write-Output "autounattend.xml 不存在.无需操作."
}

# 停止记录
Stop-Transcript

exit