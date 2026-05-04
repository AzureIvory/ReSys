$ErrorActionPreference = 'Continue'

function Remove-ProvisionedPackages {
    $selectors = @(
        'Microsoft.BingSearch'
        'Microsoft.WindowsCamera'
        'Clipchamp.Clipchamp'
        'Microsoft.549981C3F5F10'
        'Microsoft.Windows.DevHome'
        'MicrosoftCorporationII.MicrosoftFamily'
        'Microsoft.WindowsFeedbackHub'
        'Microsoft.Edge.GameAssist'
        'Microsoft.GetHelp'
        'Microsoft.Getstarted'
        'Microsoft.WindowsMaps'
        'Microsoft.MixedReality.Portal'
        'Microsoft.BingNews'
        'Microsoft.MicrosoftOfficeHub'
        'Microsoft.Office.OneNote'
        'Microsoft.OutlookForWindows'
        'Microsoft.PowerAutomateDesktop'
        'MicrosoftCorporationII.QuickAssist'
        'Microsoft.SkypeApp'
        'MicrosoftTeams'
        'MSTeams'
        'Microsoft.Wallet'
        'Microsoft.YourPhone'
    )

    $logfile = 'C:\Windows\Setup\Scripts\RemovePackages.log'
    $installed = Get-AppxProvisionedPackage -Online

    foreach ($selector in $selectors) {
        $result = [ordered]@{
            Type     = 'Package'
            Selector = $selector
        }

        $found = $installed | Where-Object { $_.DisplayName -eq $selector }

        if ($found) {
            $result.Output = $found | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction Continue
            if ($?) {
                $result.Message = 'Package removed.'
            } else {
                $result.Message = 'Package not removed.'
                $result.Error = $Error[0]
            }
        } else {
            $result.Message = 'Package not installed.'
        }

        $result | ConvertTo-Json -Depth 3 -Compress
    } *>&1 | Out-String -Stream >> $logfile
}

function Remove-WindowsCapabilitiesCustom {
    $selectors = @(
        'OneCoreUAP.OneSync'
        'App.Support.QuickAssist'
        'App.StepsRecorder'
        'Hello.Face.18967'
        'Hello.Face.Migration.18967'
        'Hello.Face.20134'
        'Microsoft.Windows.WordPad'
    )

    $logfile = 'C:\Windows\Setup\Scripts\RemoveCapabilities.log'

    $installed = Get-WindowsCapability -Online | Where-Object {
        $_.State -notin @('NotPresent', 'Removed')
    }

    foreach ($selector in $selectors) {
        $result = [ordered]@{
            Type     = 'Capability'
            Selector = $selector
        }

        $found = $installed | Where-Object {
            ($_.Name -split '~')[0] -eq $selector
        }

        if ($found) {
            $result.Output = $found | Remove-WindowsCapability -Online -ErrorAction Continue
            if ($?) {
                $result.Message = 'Capability removed.'
            } else {
                $result.Message = 'Capability not removed.'
                $result.Error = $Error[0]
            }
        } else {
            $result.Message = 'Capability not installed.'
        }

        $result | ConvertTo-Json -Depth 3 -Compress
    } *>&1 | Out-String -Stream >> $logfile
}

function Set-StartPinsCustom {
    $logfile = 'C:\Windows\Setup\Scripts\SetStartPins.log'

    if ([System.Environment]::OSVersion.Version.Build -lt 20000) {
        'Windows build is lower than 20000. Skip Start pins configuration.' >> $logfile
        return
    }

    $json = '{"pinnedList":[]}'
    $key = 'Registry::HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start'

    New-Item -Path $key -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath $key -Name 'ConfigureStartPins' -Value $json -Type String

    'Start pins configured.' >> $logfile
}

Remove-ProvisionedPackages
Remove-WindowsCapabilitiesCustom
Set-StartPinsCustom