
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Security;

namespace Windows10
{
	class Program
	{
		public static SecureString GetPassword()
		{
			var pwd = new SecureString();
			while (true) {
				ConsoleKeyInfo i = Console.ReadKey(true);
				if (i.Key == ConsoleKey.Enter) {
					break;
				} else if (i.Key == ConsoleKey.Backspace) {
					if (pwd.Length > 0) {
						pwd.RemoveAt(pwd.Length - 1);
						Console.Write("\b \b");
					}
				} else if (i.KeyChar != '\u0000') { // KeyChar == '\u0000' if the key pressed does not correspond to a printable character, e.g. F1, Pause-Break, etc
					pwd.AppendChar(i.KeyChar);
					Console.Write("*");
				}
			}
			return pwd;
		}
		public static int RunProcessAsAdmin(string exeName, string parameters)
		{
			try {
				System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
				startInfo.UseShellExecute = true;
//            startInfo.WorkingDirectory = CurrentDirectory;
//            startInfo.FileName = Path.Combine(CurrentDirectory, exeName);
				startInfo.FileName = exeName;
				startInfo.Verb = "runas";
				//MLHIDE
				startInfo.Arguments = parameters;
				startInfo.ErrorDialog = true;

				Process process = System.Diagnostics.Process.Start(startInfo);
				process.WaitForExit();
				return process.ExitCode;
			} catch (Win32Exception ex) {
				
				switch (ex.NativeErrorCode) {
					case 1223:
						return ex.NativeErrorCode;
					default:
						return 0;
				}

			} catch (Exception ex) {
			
				return 0;
			}
		}
		public static void Main(string[] args)
		{
//			string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
//			var index = userName.IndexOf("\\");
//			if (index != -1) {
//				userName = userName.Substring(index + 1);
//			}
//			Console.WriteLine("当前用户名：{0}", userName);
//			var pass = GetPassword();
			

//			Process.Start("rem", "USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!","admin", pass, "");
//			Process.Start("rem", "https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference","admin", pass, "");
//			Process.Start("rem", "To also disable Windows Defender Security Center include this","admin", pass, "");
//			Process.Start("rem", "reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f","admin", pass, "");
//			Process.Start("rem", "1 - Disable Real-time protection","admin", pass, "");
			Process.Start("reg", "delete \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /f");
			
			Process.Start("reg", "add \"HKLM\\Software\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d \"1\" /f");
			
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableRoutinelyTakingAction\" /t REG_DWORD /d \"1\" /f");
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
//			Process.Start("rem", "0 - Disable Logging","admin", pass, "");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f");
//			Process.Start("rem", "Disable WD Tasks","admin", pass, "");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable");
			Process.Start("schtasks", "/Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Disable");
//			Process.Start("rem", "Disable WD systray icon","admin", pass, "");
			Process.Start("reg", "delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\" /v \"Windows Defender\" /f");
			Process.Start("reg", "delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Defender\" /f");
			Process.Start("reg", "delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WindowsDefender\" /f");
//			Process.Start("rem", "Remove WD context menu","admin", pass, "");
			Process.Start("reg", "delete \"HKCR\\*\\shellex\\ContextMenuHandlers\\EPP\" /f");
			Process.Start("reg", "delete \"HKCR\\Directory\\shellex\\ContextMenuHandlers\\EPP\" /f");
			Process.Start("reg", "delete \"HKCR\\Drive\\shellex\\ContextMenuHandlers\\EPP\" /f");
//			Process.Start("rem", "Disable WD services","admin", pass, "");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdBoot\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdFilter\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
//			Process.Start("rem", "Run \"Disable WD.bat\" again to disable WD services","admin", pass, "");
			
//			
			Process.Start("sc.exe", "config wuauserv start=disabled");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\wuauserv\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			Process.Start("reg", "add \"HKLM\\System\\CurrentControlSet\\Services\\WpnUserService\" /v \"Start\" /t REG_DWORD /d \"4\" /f");
			
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"AllowCortana\" /t REG_DWORD /d \"0\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"AllowCortanaAboveLock\" /t REG_DWORD /d \"0\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"DisableWebSearch\" /t REG_DWORD /d \"1\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"ConnectedSearchUseWeb\" /t REG_DWORD /d \"0\" /f");
			Process.Start("reg", "add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"ConnectedSearchUseWebOverMeteredConnections\" /t REG_DWORD /d \"0\" /f");
//			var o =	Process.Start(new ProcessStartInfo {
//				FileName = "cmd",
//				Arguments = "/k reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell\" /v \"UseActionCenterExperience\" /t REG_DWORD /d \"0\" /f",
//				UseShellExecute = false,
//				//RedirectStandardOutput = true,
//				UserName = userName,
//				Password = pass,
//			});
//			
//			while (!o.StandardOutput.EndOfStream) {
//				string line = o.StandardOutput.ReadLine();
//				Console.WriteLine(line);
//			}
//			o.WaitForExit();
			Process.Start("reg", "add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell\" /v \"UseActionCenterExperience\" /t REG_DWORD /d \"0\" /f");
// reg add "HKLM\System\CurrentControlSet\Services\WpnUserService" /v "Start" /t REG_DWORD /d "4" /f
		

		}
	}
}