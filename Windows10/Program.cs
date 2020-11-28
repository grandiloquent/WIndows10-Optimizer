
using System;
using System.Diagnostics;

namespace Windows10
{
	class Program
	{
		public static void Main(string[] args)
		{
//			Process.Start("rem", "USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!");
//			Process.Start("rem", "https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference");
//			Process.Start("rem", "To also disable Windows Defender Security Center include this");
//			Process.Start("rem", "reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
//			Process.Start("rem", "1 - Disable Real-time protection");
			Process.Start("reg", "delete \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine\" /v \"MpEnablePus\" /t REG_DWORD /d \"0\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableOnAccessProtection\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableScanOnRealtimeEnable\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Reporting\" /v \"DisableEnhancedNotifications\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"DisableBlockAtFirstSeen\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SpynetReporting\" /t REG_DWORD /d \"0\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SubmitSamplesConsent\" /t REG_DWORD /d \"0\" /f");
//			Process.Start("rem", "0 - Disable Logging");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
//			Process.Start("rem", "Disable WD Tasks");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Disable");
//			Process.Start("rem", "Disable WD systray icon");
			Process.Start("reg", "delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\" /v \"Windows Defender\" /f");
			Process.Start("reg", "delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Defender\" /f");
			Process.Start("reg", "delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WindowsDefender\" /f");
//			Process.Start("rem", "Remove WD context menu");
			Process.Start("reg", "delete \"HKCR\\*\\shellex\\ContextMenuHandlers\\EPP\" /f");
			Process.Start("reg", "delete \"HKCR\\Directory\\shellex\\ContextMenuHandlers\\EPP\" /f");
			Process.Start("reg", "delete \"HKCR\\Drive\\shellex\\ContextMenuHandlers\\EPP\" /f");
//			Process.Start("rem", "Disable WD services");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdBoot\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdFilter\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
//			Process.Start("rem", "Run \"Disable WD.bat\" again to disable WD services");
			
			
			Process.Start("sc.exe", "config wuauserv start=disabled");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\wuauserv\" /v \"Start\" /t REG_DWORD /d \"4\" /f");

		}
	}
}