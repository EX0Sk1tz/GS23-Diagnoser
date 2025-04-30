using System.Text;
using System.Windows;
using System.Diagnostics;
using System.Management;
using System.Windows.Controls;
using System.Windows.Media;
using System.Text.Json;
using System.IO;
using System.Net.Http;
using System.Windows.Input;

namespace GS23_Diagnoser
{
    public partial class MainWindow : Window
    {
        public MainWindow() => InitializeComponent();

        private DiagnosticResult currentResult = new();

        private async void CheckAll_Click(object sender, RoutedEventArgs e)
        {
            ResultPanel.Children.Clear();
            LogBox.Clear();
            StatusLabel.Text = "Status: Running...";
            string os = Environment.OSVersion.VersionString;
            int total = 14;
            int current = 0;

            currentResult = new DiagnosticResult
            {
                OSVersion = Environment.OSVersion.VersionString,
                Timestamp = DateTime.Now
            };


            void Log(string msg)
            {
                LogBox.AppendText("→ " + msg + Environment.NewLine);
                LogBox.ScrollToEnd();
            }

            void UpdateProgress()
            {
                current++;
                ProgressLabel.Text = $"Progress: {current} / {total}";
            }

            AddTextResult("🧩 System Information");
            var (isSupported, versionString) = CheckWindowsVersion();
            AddResult("OS Version", isSupported, versionString, versionString, true);
            currentResult.Checks["OS Version"] = versionString;
            UpdateProgress();


            Log("Checking UAC status...");
            bool uac = await Task.Run(CheckUAC);
            AddResult("UAC", uac, "DISABLED", "ENABLED", false);
            AddTextResult("");
            currentResult.Checks["UAC"] = uac ? "ENABLED" : "DISABLED";
            UpdateProgress();

            AddTextResult("🛡 Security Checks");

            Log("Checking Antivirus software...");
            bool antivirus = await Task.Run(CheckAntivirus);
            currentResult.Checks["Antivirus"] = antivirus ? "FOUND" : "None";
            UpdateProgress();

            Log("Checking Defender Tamper Protection...");
            bool tamper = await Task.Run(CheckTamperProtection);
            AddResult("Tamper Protection", tamper, "DISABLED", "ENABLED", false);
            currentResult.Checks["Tamper Protection"] = tamper ? "ENABLED" : "DISABLED";
            UpdateProgress();

            Log("Checking Secure Boot...");
            bool secureBoot = await Task.Run(CheckSecureBoot);
            AddResult("Secure Boot", secureBoot, "OFF or Unsupported", "ON", false);
            currentResult.Checks["Secure Boot"] = secureBoot ? "ON" : "OFF or Unsupported";
            UpdateProgress();

            Log("Checking Test Mode...");
            bool testMode = await Task.Run(CheckTestMode);
            AddResult("Test Mode", testMode, "DISABLED", "ENABLED", true);
            currentResult.Checks["Test Mode"] = testMode ? "ENABLED" : "DISABLED";
            UpdateProgress();

            Log("Checking Memory Integrity...");
            bool hvci = await Task.Run(CheckHVCI);
            AddResult("Memory Integrity", hvci, "DISABLED", "ENABLED", false);
            AddTextResult("");
            currentResult.Checks["Memory Integrity"] = hvci ? "ENABLED" : "DISABLED";
            UpdateProgress();

            AddTextResult("🎮 Anti-Cheat Detection");

            Log("Checking for Anti-Cheat Services...");
            bool antiCheat = await Task.Run(CheckAntiCheat);
            currentResult.Checks["Detected Anti-Cheats"] = antiCheat ? "FOUND" : "None";
            UpdateProgress();

            Log("Checking Anti-Cheat Drivers...");
            bool acDriver = await Task.Run(CheckACDrivers);
            currentResult.Checks["Detected AC Driver"] = acDriver ? "FOUND" : "None";
            UpdateProgress();

            Log("Checking for Overlay Conflicts...");
            bool overlays = await Task.Run(CheckOverlayConflicts);
            AddTextResult("");
            currentResult.Checks["Overlay Conflicts"] = overlays ? "FOUND" : "None";
            UpdateProgress();

            AddTextResult("⚙️ System Compatibility");

            Log("Checking CSM (Legacy Boot Mode)...");
            bool csm = await Task.Run(IsCsmMode);
            AddResult("Boot Mode (CSM)", csm, "UEFI", "Legacy (CSM)", true);
            currentResult.Checks["Boot Mode"] = csm ? "Legacy (CSM)" : "UEFI";
            UpdateProgress();

            Log("Checking Virtualization...");
            bool virt = await Task.Run(CheckVirtualization);
            AddResult("Virtualization", virt, "DISABLED", "ENABLED", false);
            currentResult.Checks["Virtualization"] = virt ? "ENABLED" : "DISABLED";
            UpdateProgress();

            Log("Checking VC++ Runtime Presence...");
            bool runtimes = await Task.Run(CheckVCRedist);
            AddResult("VC++ Runtimes", runtimes, "Missing", "Installed", true);
            currentResult.Checks["VC++ Runtimes"] = runtimes ? "Installed" : "Missing";
            UpdateProgress();

            Log("Checking TPM...");
            bool tpm = await Task.Run(CheckTPM);
            AddResult("TPM", tpm, "DISABLED or Not Present", "ENABLED", false);
            AddTextResult("");
            currentResult.Checks["TPM"] = tpm ? "ENABLED" : "DISABLED or Not Present";
            UpdateProgress();

            Log("Running HWID trust analysis...");
            int trustScore = EvaluateTrustScore(out var warnings);
            currentResult.TrustScore = trustScore;
            currentResult.TrustWarnings = warnings;

            string trustLabel = trustScore switch
            {
                <= 10 => "Excellent (No signs of spoofing)",
                <= 30 => "Moderate (Mild mismatch)",
                <= 60 => "Suspicious",
                _ => "Likely Spoofed"
            };

            Brush trustColor = trustScore <= 10 ? Brushes.LimeGreen :
                               trustScore <= 30 ? Brushes.Orange :
                               Brushes.Red;

            ResultPanel.Children.Add(new TextBlock
            {
                Text = $"🔒 HWID Trust Score: {trustScore}/100 – {trustLabel}",
                Foreground = trustColor,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 16,
                Margin = new Thickness(0, 10, 0, 0)
            });

            foreach (string warn in warnings)
            {
                ResultPanel.Children.Add(new TextBlock
                {
                    Text = warn,
                    Foreground = Brushes.Orange,
                    FontSize = 12,
                    Margin = new Thickness(0, 2, 0, 0)
                });
            }


            Log("✅ All checks completed.");
            StatusLabel.Text = "Status: Completed";

        }

        private void AddTextResult(string text)
        {
            Dispatcher.Invoke(() =>
            {
                ResultPanel.Children.Add(new TextBlock
                {
                    Text = text,
                    Foreground = Brushes.LightGray,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 16,
                    Margin = new Thickness(0, 4, 0, 0)
                });
            });
        }

        private void AddResult(string label, bool state, string offText, string onText, bool idealState)
        {
            string displayText = $"{label}: {(state ? onText : offText)}";

            // Farbe anpassen je nachdem, was „gut“ ist
            Brush color;
            if (state == idealState)
                color = Brushes.LimeGreen;
            else
                color = Brushes.IndianRed;

            var tb = new TextBlock
            {
                Text = displayText,
                Foreground = color,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 16,
                Margin = new Thickness(0, 4, 0, 0)
            };

            ResultPanel.Children.Add(tb);
        }

        private (bool isSupported, string versionString) CheckWindowsVersion()
        {
            var ver = Environment.OSVersion.Version;
            // Windows 10: Major 10, Build < 22000 (all Win10 releases)
            if (ver.Major == 10 && ver.Build < 22000)
                return (true, $"Windows 10 (Build {ver.Build})");

            // Windows 11: builds 22000 (21H2), 22621 (22H2), 22631 (23H2) are supported
            if (ver.Major == 10 && (ver.Build == 22000 || ver.Build == 22621 || ver.Build == 22631))
                return (true, $"Windows 11 {(ver.Build == 22000 ? "21H2" : ver.Build == 22621 ? "22H2" : "23H2")} (Build {ver.Build})");

            // Windows 11 24H2 or higher (build 26100+)
            if (ver.Major == 10 && ver.Build >= 26100)
                return (false, $"Windows 11 24H2 or newer (Build {ver.Build}) – NOT SUPPORTED");

            // Anything else
            return (false, $"Windows {ver.Major}.{ver.Minor} (Build {ver.Build}) – Unknown or unsupported");
        }


        private bool CheckSecureBoot()
        {
            try
            {
                var p = new Process
                {
                    StartInfo = new ProcessStartInfo("powershell", "Confirm-SecureBootUEFI")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                p.Start();
                string output = p.StandardOutput.ReadToEnd();
                return output.Trim() == "True";
            }
            catch { return false; }
        }

        private bool CheckTestMode()
        {
            var p = Process.Start(new ProcessStartInfo("cmd.exe", "/c bcdedit")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            string output = p.StandardOutput.ReadToEnd();
            return output.ToLower().Contains("testsigning yes");
        }

        private bool CheckHVCI()
        {
            try
            {
                var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
                if (key != null)
                    return (int)key.GetValue("Enabled", 0) == 1;
            }
            catch { }
            return false;
        }

        private bool CheckVirtualization()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
                foreach (var item in searcher.Get())
                {
                    return (bool)item["VirtualizationFirmwareEnabled"];
                }
            }
            catch { }
            return false;
        }

        private bool CheckTPM()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\CIMV2\\Security\\MicrosoftTpm", "SELECT * FROM Win32_Tpm");
                foreach (var tpm in searcher.Get())
                {
                    return (bool)tpm["IsEnabled_InitialValue"];
                }
            }
            catch { }
            return false;
        }

        private bool CheckAntiCheat()
        {
            string[] knownACs = {
                "vgc", "vgk", "EasyAntiCheat", "EasyAntiCheatService",
                "BEService", "BEDaisy", "FaceIt", "faceitclient",
                "XignCode", "Xhunter", "GameGuard", "nProtect",
                "Riot Vanguard", "Vanguard"
            };

            List<string> foundACs = new();

            try
            {
                // Dienste durchsuchen
                using var sc = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
                foreach (ManagementObject service in sc.Get())
                {
                    string name = service["Name"]?.ToString() ?? "";
                    string displayName = service["DisplayName"]?.ToString() ?? "";

                    foreach (var ac in knownACs)
                    {
                        if ((name.Contains(ac, StringComparison.OrdinalIgnoreCase) ||
                             displayName.Contains(ac, StringComparison.OrdinalIgnoreCase)) &&
                            !foundACs.Contains(ac))
                        {
                            foundACs.Add(ac);
                        }
                    }
                }

                // Prozesse durchsuchen
                var processes = Process.GetProcesses();
                foreach (var proc in processes)
                {
                    foreach (var ac in knownACs)
                    {
                        if (proc.ProcessName.IndexOf(ac, StringComparison.OrdinalIgnoreCase) >= 0 &&
                            !foundACs.Contains(ac))
                        {
                            foundACs.Add(ac);
                        }
                    }
                }
            }
            catch { }

            if (foundACs.Count > 0)
            {
                AddTextResult("Detected Anti-Cheats: " + string.Join(", ", foundACs));
                return true;
            }

            AddTextResult("Detected Anti-Cheats: None");
            return false;
        }

        private bool CheckACDrivers()
        {
            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.Arguments = "/c driverquery /fo csv /nh";
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                string[] knownDrivers = {
                    "vgk", "vgc", "bedaisy", "easyanticheat",
                    "faceit", "xhunter", "xigncode", "mhyprot", "iqvw64e", "npgm", "gameguard"
                };

                List<string> foundDrivers = new();

                foreach (string line in lines)
                {
                    string[] fields = line.Split(',');

                    if (fields.Length > 0)
                    {
                        string driverName = fields[0].Trim('"').ToLower();

                        foreach (string known in knownDrivers)
                        {
                            if (driverName.Contains(known) && !foundDrivers.Contains(driverName))
                            {
                                foundDrivers.Add(driverName);
                            }
                        }
                    }
                }

                if (foundDrivers.Count > 0)
                {
                    AddTextResult("Detected AC Driver: " + string.Join(", ", foundDrivers));
                    return true;
                }

                AddTextResult("Detected AC Driver: None");
            }
            catch { }

            return false;
        }

        private bool CheckVCRedist()
        {
            try
            {
                var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64");
                if (key != null && (int)key.GetValue("Installed", 0) == 1)
                    return true;
            }
            catch { }
            return false;
        }

        private bool CheckUAC()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key != null)
                {
                    int value = (int)key.GetValue("EnableLUA", 1); // 1 = UAC on, 0 = off
                    return value == 1;
                }
            }
            catch { }
            return false; // assume off if unknown
        }

        private bool CheckAntivirus()
        {
            try
            {
                var avNames = new List<string>();
                var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");

                foreach (ManagementObject av in searcher.Get())
                {
                    string name = av["displayName"]?.ToString() ?? "";
                    if (!string.IsNullOrEmpty(name))
                    {
                        avNames.Add(name);
                    }
                }

                // Check Defender state if it's in the list
                if (avNames.Any(n => n.IndexOf("defender", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    bool running = IsDefenderRunning();
                    string note = running ? " (ENABLED)" : " (DISABLED)";
                    avNames = avNames.Select(n =>
                        n.IndexOf("defender", StringComparison.OrdinalIgnoreCase) >= 0 ? n + note : n
                    ).ToList();
                }

                if (avNames.Count > 0)
                {
                    AddTextResult("Antivirus Detected: " + string.Join(", ", avNames));
                    return true;
                }
            }
            catch { }

            AddTextResult("Antivirus Detected: None");
            return false;
        }

        private bool IsDefenderRunning()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='WinDefend'");
                foreach (ManagementObject service in searcher.Get())
                {
                    string status = service["State"]?.ToString() ?? "";
                    return status.Equals("Running", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch { }

            return false;
        }

        private bool CheckTamperProtection()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "Get-MpPreference | Select -ExpandProperty EnableTamperProtection",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd().Trim();

                if (int.TryParse(output, out int result))
                {
                    return result == 1; // 1 = enabled, 0 = disabled
                }
            }
            catch { }

            return false; // assume off if we can’t read it
        }

        private bool CheckOverlayConflicts()
        {
            string[] overlayProcesses = {
                "RTSS", "obs64", "obs32", "obs", "Discord", "GameBar", "SteamOverlay", "NVIDIA Share",
                "NVIDIA Container", "NVIDIA ShadowPlay", "Overwolf", "MSIAfterburner", "Lconnect3", "lianli",
                "ArmouryCrate", "ACDaemon", "ArmourySwAgent", "ArmouryLiveUpdate", "NZXT"
            };

            var conflicts = new List<string>();

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    foreach (var name in overlayProcesses)
                    {
                        if (proc.ProcessName.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0 &&
                            !conflicts.Contains(name))
                        {
                            conflicts.Add(name);
                        }
                    }
                }
            }
            catch { }

            if (conflicts.Count > 0)
            {
                AddTextResult("Overlay Conflicts Detected: " + string.Join(", ", conflicts));
                return true;
            }

            AddTextResult("Overlay Conflicts Detected: None");
            return false;
        }

        private bool IsCsmMode()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo("bcdedit")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd().ToLower();

                // If path is winload.exe => Legacy
                // If winload.efi => UEFI
                return output.Contains("path") && output.Contains("winload.exe");
            }
            catch { }

            return false;
        }

        private int EvaluateTrustScore(out List<string> warnings)
        {
            int score = 0;
            warnings = new();

            try
            {
                // Volume Serial via WMI
                string wmiDisk = new ManagementObjectSearcher("SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID = 'C:'")
                                 .Get().Cast<ManagementObject>().FirstOrDefault()?["VolumeSerialNumber"]?.ToString() ?? "";

                // Volume Serial via WinAPI
                StringBuilder sb = new(256);
                GetVolumeInformation("C:\\", null, 0, out uint serial, out _, out _, sb, (uint)sb.Capacity);
                string winapiDisk = serial.ToString("X");

                if (!string.Equals(wmiDisk, winapiDisk, StringComparison.OrdinalIgnoreCase))
                {
                    score += 25;
                    warnings.Add("⚠️ Disk serial mismatch between WMI and API.");
                }

                // CPU ID
                string cpuId = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor")
                                .Get().Cast<ManagementObject>().FirstOrDefault()?["ProcessorId"]?.ToString() ?? "";

                if (string.IsNullOrEmpty(cpuId) || cpuId == "0000000000000000")
                {
                    score += 20;
                    warnings.Add("⚠️ CPU ID invalid or spoofed.");
                }

                // BIOS
                string bios = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS")
                                .Get().Cast<ManagementObject>().FirstOrDefault()?["SerialNumber"]?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(bios) || bios.ToLower().Contains("default"))
                {
                    score += 20;
                    warnings.Add("⚠️ BIOS serial suspicious or default.");
                }

                // MAC Address
                var macs = new ManagementObjectSearcher("SELECT MACAddress FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL")
                            .Get().Cast<ManagementObject>()
                            .Select(mo => mo["MACAddress"]?.ToString()).Where(m => !string.IsNullOrWhiteSpace(m)).ToList();
                if (macs.Any(mac => mac.StartsWith("00:05:69") || mac.StartsWith("00:0C:29")))
                {
                    score += 20;
                    warnings.Add("⚠️ VMware MAC address detected.");
                }

                // Machine GUID
                string machineGuid = Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", "")?.ToString() ?? "";
                if (string.IsNullOrEmpty(machineGuid))
                {
                    score += 15;
                    warnings.Add("⚠️ Machine GUID missing or blank.");
                }

            }
            catch (Exception ex)
            {
                warnings.Add("❌ Trust check failed: " + ex.Message);
                score += 10;
            }

            return score;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern bool GetVolumeInformation(
            string lpRootPathName,
            StringBuilder lpVolumeNameBuffer,
            int nVolumeNameSize,
            out uint lpVolumeSerialNumber,
            out uint lpMaximumComponentLength,
            out uint lpFileSystemFlags,
            StringBuilder lpFileSystemNameBuffer,
            uint nFileSystemNameSize
        );

        private async void CreateRestorePoint_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StatusLabel.Text = "Creating restore point...";
                Mouse.OverrideCursor = Cursors.Wait;

                bool success = await Task.Run(() => CreateRestorePoint());

                Mouse.OverrideCursor = null;

                if (success)
                {
                    MessageBox.Show("✅ Restore point was created successfully.",
                                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusLabel.Text = "Restore point created!";
                }
                else
                {
                    MessageBox.Show("⚠ Failed to create restore point.\nPlease ensure System Protection is enabled and try again.",
                                    "Restore Point Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    StatusLabel.Text = "Failed to create restore point!";
                }
            }
            catch (Exception ex)
            {
                Mouse.OverrideCursor = null;
                MessageBox.Show("❌ An error occurred while creating the restore point:\n" + ex.Message,
                                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusLabel.Text = "An error occurred!";
            }
        }

        private bool CreateRestorePoint()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "Checkpoint-Computer -Description 'GS23 Diagnoser Restore' -RestorePointType MODIFY_SETTINGS",
                    Verb = "runas",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    string error = proc.StandardError.ReadToEnd();
                    proc.WaitForExit();

                    if (proc.ExitCode == 0)
                        return true;

                    MessageBox.Show("⚠ PowerShell error:\n" + error,
                                    "Restore Point Error Details", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("❌ Failed to start PowerShell:\n" + ex.Message,
                                "Execution Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private void ExportToJson(object sender, RoutedEventArgs e)
        {
            try
            {
                string json = JsonSerializer.Serialize(currentResult, new JsonSerializerOptions { WriteIndented = true });
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"diagnostic_{DateTime.Now:yyyyMMdd_HHmmss}.json");
                File.WriteAllText(path, json);

                MessageBox.Show("Diagnostic exported to:\n" + path, "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Export failed:\n" + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        private void CopyToClipboard(object sender, RoutedEventArgs e)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Diagnostic created: {currentResult.Timestamp}");
            sb.AppendLine($"OS: {currentResult.OSVersion}");
            sb.AppendLine();

            foreach (var kv in currentResult.Checks)
                sb.AppendLine($"{kv.Key}: {kv.Value}");

            sb.AppendLine();
            sb.AppendLine($"🔒 HWID Trust Score: {currentResult.TrustScore}/100");

            if (currentResult.TrustWarnings.Any())
            {
                sb.AppendLine("⚠️ Trust Warnings:");
                foreach (var warning in currentResult.TrustWarnings)
                    sb.AppendLine(" - " + warning);
            }

            Clipboard.SetText(sb.ToString());
            MessageBox.Show("Copied to clipboard.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }


        private async void SendToDiscord(object sender, RoutedEventArgs e)
        {
            if (currentResult == null || currentResult.Checks.Count == 0)
            {
                MessageBox.Show("Please run a diagnostic before sending to Discord.", "No Data", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            await SendDiscordWebhook(currentResult);
        }


        private async Task SendDiscordWebhook(DiagnosticResult result)
        {
            var embedFields = result.Checks.Select(kvp => new
            {
                name = kvp.Key,
                value = kvp.Value,
                inline = true
            }).ToList();

            embedFields.Add(new
            {
                name = "🔒 HWID Trust Score",
                value = $"{result.TrustScore}/100",
                inline = false
            });

            if (result.TrustWarnings.Any())
            {
                embedFields.Add(new
                {
                    name = "⚠️ Trust Warnings",
                    value = string.Join("\n", result.TrustWarnings),
                    inline = false
                });
            }

            var embed = new
            {
                title = "🛠 GS23 Diagnoser Result",
                description = $"**OS Version:** {result.OSVersion}\n**Timestamp:** {result.Timestamp:yyyy-MM-dd HH:mm:ss}",
                color = 5763719, // blue-green
                fields = embedFields,
                timestamp = result.Timestamp.ToUniversalTime().ToString("o")
            };

            var payload = new
            {
                embeds = new[] { embed }
            };

            try
            {
                using var client = new HttpClient();
                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                string webhookUrl = "https://discord.com/api/webhooks/1361289534993596446/kjaXIxMe1bgR6VNvG8QQFOa_08QSZPZBAd0Z7ihywUzJSLzkJsQySmEHBr05E5N25TqN";
                var response = await client.PostAsync(webhookUrl, content);

                if (response.IsSuccessStatusCode)
                {
                    MessageBox.Show("✅ Sent to Discord successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show($"❌ Discord webhook failed:\n{response.StatusCode}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("❌ Failed to send to Discord:\n" + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


    }

    public class DiagnosticResult
    {
        public string OSVersion { get; set; }
        public Dictionary<string, string> Checks { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public int TrustScore { get; set; }
        public List<string> TrustWarnings { get; set; } = new();

    };

}
