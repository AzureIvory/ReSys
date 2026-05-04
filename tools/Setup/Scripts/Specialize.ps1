$scripts = @(
	{
		reg.exe add "HKLM\SYSTEM\Setup\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f;
	};
	{
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f;
	};
	{
		Remove-Item -LiteralPath 'Registry::HKLM\Software\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate' -Force -ErrorAction 'SilentlyContinue';
	};
	{
		Remove-Item -LiteralPath 'C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk', 'C:\Windows\System32\OneDriveSetup.exe', 'C:\Windows\SysWOW64\OneDriveSetup.exe' -ErrorAction 'Continue';
	};
	{
		Remove-Item -LiteralPath 'Registry::HKLM\Software\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' -Force -ErrorAction 'SilentlyContinue';
	};
	{
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f;
	};
	{
		Get-Content -LiteralPath 'C:\Windows\Setup\Scripts\Clean.ps1' -Raw | Invoke-Expression;
	};
	{
		net.exe accounts /maxpwage:UNLIMITED;
	};
	{
		Register-ScheduledTask -TaskName 'PauseWindowsUpdate' -Xml $( Get-Content -LiteralPath 'C:\Windows\Setup\Scripts\PauseWindowsUpdate.xml' -Raw );
	};
	{
		reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableNotifications /t REG_DWORD /d 1 /f;
	};
	{
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f;
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v ServiceEnabled /t REG_DWORD /d 0 /f;
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v NotifyMalicious /t REG_DWORD /d 0 /f;
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v NotifyPasswordReuse /t REG_DWORD /d 0 /f;
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v NotifyUnsafeApp /t REG_DWORD /d 0 /f;
		reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v HideSystray /t REG_DWORD /d 1 /f;
	};
	{
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
	};
	{
		Set-ExecutionPolicy -Scope 'LocalMachine' -ExecutionPolicy 'RemoteSigned' -Force;
	};
	{
		fsutil.exe behavior set disableLastAccess 1;
	};
	{
		reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f;
		reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f;
	};
	{
		Register-ScheduledTask -TaskName 'MoveActiveHours' -Xml $( Get-Content -LiteralPath 'C:\Windows\Setup\Scripts\MoveActiveHours.xml' -Raw );
	};
	{
		reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f;
	};
	{
		reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f;
	};
	{
		reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f;
	};
	{
		reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d 1 /f;
	};
	{
		reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f;
	};
	{
		reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v BackgroundModeEnabled /t REG_DWORD /d 0 /f;
		reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v StartupBoostEnabled /t REG_DWORD /d 0 /f;
	};
);

& {
  [float] $complete = 0;
  [float] $increment = 100 / $scripts.Count;
  foreach( $script in $scripts ) {
    Write-Progress -Activity 'Running scripts to customize your Windows installation. Do not close this window.' -PercentComplete $complete;
    '*** Will now execute command «{0}».' -f $(
      $str = $script.ToString().Trim() -replace '\s+', ' ';
      $max = 100;
      if( $str.Length -le $max ) {
        $str;
      } else {
        $str.Substring( 0, $max - 1 ) + '…';
      }
    );
    $start = [datetime]::Now;
    & $script;
    '*** Finished executing command after {0:0} ms.' -f [datetime]::Now.Subtract( $start ).TotalMilliseconds;
    "`r`n" * 3;
    $complete += $increment;
  }
} *>&1 | Out-String -Stream >> "C:\Windows\Setup\Scripts\Specialize.log";