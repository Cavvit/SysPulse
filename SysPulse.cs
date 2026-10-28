using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

// SECURITY: P/Invoke DLLs (dwmapi, psapi, ...) only resolved from System32 -> blocks DLL planting in app folder.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace SysPulse
{
    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetDefaultDllDirectories(uint DirectoryFlags);
        public const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll")]
        public static extern int EmptyWorkingSet(IntPtr hwProc);

        [DllImport("ntdll.dll")]
        public static extern uint NtSetSystemInformation(int InfoClass, IntPtr Info, int Length);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        [DllImport("dwmapi.dll")]
        public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetProcessInformation(IntPtr hProcess, int ProcessInformationClass, IntPtr ProcessInformation, uint ProcessInformationSize);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_POWER_THROTTLING_STATE
        {
            public uint Version;
            public uint ControlMask;
            public uint StateMask;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
            public MEMORYSTATUSEX()
            {
                this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            }
        }

        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int TOKEN_QUERY = 0x00000008;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const int SystemMemoryListInformation = 80;
        public const int MemoryPurgeStandbyList = 4;
        public const int MemoryFlushModifiedList = 3;
        public const int MemoryEmptyWorkingSets = 2;

        public const int ProcessPowerThrottling = 4;
        public const uint PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1;
        public const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;

        public static bool SetProcessEcoQoS(IntPtr processHandle, bool enableEco)
        {
            try
            {
                PROCESS_POWER_THROTTLING_STATE state = new PROCESS_POWER_THROTTLING_STATE
                {
                    Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                    ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                    StateMask = enableEco ? PROCESS_POWER_THROTTLING_EXECUTION_SPEED : 0u
                };
                int size = Marshal.SizeOf(typeof(PROCESS_POWER_THROTTLING_STATE));
                IntPtr ptr = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(state, ptr, false);
                    return SetProcessInformation(processHandle, ProcessPowerThrottling, ptr, (uint)size);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool EnablePrivilege(string privilegeName)
        {
            IntPtr htok = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok))
                    return false;
                TokPriv1Luid tp = new TokPriv1Luid { Count = 1, Luid = 0, Attr = SE_PRIVILEGE_ENABLED };
                if (!LookupPrivilegeValue(null, privilegeName, ref tp.Luid))
                    return false;
                // AdjustTokenPrivileges returns true even if privilege not held -> check last error (ERROR_NOT_ALL_ASSIGNED = 1300)
                bool ok = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return ok && Marshal.GetLastWin32Error() == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                // SECURITY: do not leak privileged token handle
                if (htok != IntPtr.Zero) CloseHandle(htok);
            }
        }

        public static void PurgeStandbyMemory(out bool standbySuccess)
        {
            standbySuccess = false;
            EnablePrivilege("SeProfileSingleProcessPrivilege");
            EnablePrivilege("SeIncreaseQuotaPrivilege");

            IntPtr ptr = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                Marshal.WriteInt32(ptr, MemoryEmptyWorkingSets);
                NtSetSystemInformation(SystemMemoryListInformation, ptr, sizeof(int));

                Marshal.WriteInt32(ptr, MemoryFlushModifiedList);
                NtSetSystemInformation(SystemMemoryListInformation, ptr, sizeof(int));

                Marshal.WriteInt32(ptr, MemoryPurgeStandbyList);
                uint status = NtSetSystemInformation(SystemMemoryListInformation, ptr, sizeof(int));
                standbySuccess = (status == 0);
            }
            catch
            {
                standbySuccess = false;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }

    public class MainForm : Form
    {
        // Universal OEM & Hardware Control Software Whitelist (Protects whatever brand the user owns)
        private readonly Dictionary<string, string> OemProcessCatalog = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // ASUS / ROG / TUF
            { "ArmouryCrate", "ASUS Armoury Crate" },
            { "ArmouryCrate.Service", "ASUS Armoury Crate" },
            { "ArmouryCrate.UserSessionHelper", "ASUS Armoury Crate" },
            { "ArmouryCrate.DenoiseAI", "ASUS AI Noise Canceling" },
            { "ResourceMonitorOSD", "ASUS FPS/Donanım Göstergesi" },
            { "GHelper", "ASUS G-Helper" },
            { "AsusOptimization", "ASUS Sistem Kontrolü" },
            { "AsusOptimizationStartupTask", "ASUS Sistem Kontrolü" },
            { "LightingService", "ASUS Aura Sync" },
            { "ROGLiveService", "ASUS ROG Servisi" },
            { "asus_framework", "ASUS Framework" },
            { "AsusAppService", "ASUS App Service" },
            { "AsusSoftwareManagerAgent", "ASUS Software Manager" },
            { "AcPowerNotification", "ASUS Güç Bildirimi" },
            { "Aura Wallpaper Service", "ASUS Aura Wallpaper" },
            { "RefreshRateService", "ASUS Ekran Yenileme Servisi" },
            // Lenovo / Legion
            { "LenovoVantage", "Lenovo Vantage" },
            { "LenovoVantageService", "Lenovo Vantage" },
            { "Lenovo.Modern.ImController", "Lenovo Sistem Kontrolü" },
            { "Lenovo Legion Toolkit", "Lenovo Legion Toolkit" },
            // HP / OMEN / Victus
            { "OmenCommandCenterBackground", "HP OMEN Gaming Hub" },
            { "OmenCap", "HP OMEN Kontrolcüsü" },
            { "HPSystemEventUtilityHost", "HP Sistem Aracı" },
            // MSI
            { "MSI.CentralServer", "MSI Center" },
            { "MSI Center", "MSI Center" },
            { "Dragon Center", "MSI Dragon Center" },
            // Acer / Nitro / Predator
            { "NitroSense", "Acer NitroSense" },
            { "PredatorSense", "Acer PredatorSense" },
            { "AcerSysMonitorService", "Acer Sistem Monitörü" },
            // Dell / Alienware
            { "AWCC", "Alienware Command Center" },
            { "AWCC.Background.Server", "Alienware Command Center" },
            { "Dell.DCF.UA.Bradbury.API.SubAgent", "Dell Güç/Sistem Aracı" },
            // Monster / Casper / Tongfang / Clevo
            { "ControlCenter", "Donanım Kontrol Merkezi" },
            { "OSDService", "Donanım Ekran Göstergesi (OSD)" },
            { "GamingCenterU", "Kontrol Merkezi" },
            // Genel Donanım İzleme & OSD Araçları
            { "RTSS", "RivaTuner OSD" },
            { "RTSSHooksLoader64", "RivaTuner OSD" },
            { "MSIAfterburner", "MSI Afterburner" },
            { "HWiNFO64", "HWiNFO Monitör" }
        };

        // Core OS, Audio, Display & Security Critical Processes (Never killed)
        private readonly HashSet<string> CoreSystemWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "System", "Idle", "Registry", "Secure System", "Memory Compression", "smss", "csrss", "wininit",
            "services", "lsass", "svchost", "fontdrvhost", "winlogon", "dwm", "explorer", "sihost",
            "taskhostw", "ctfmon", "audiodg", "RtkAudUService64", "DtsApo4Service",
            "NVDisplay.Container", "nvcontainer", "AMDRSServ", "RadeonSoftware", "igfxEM", "igfxCUIService",
            "MsMpEng", "MpDefenderCoreService", "SecurityHealthService",
            "ShellExperienceHost", "StartMenuExperienceHost", "TextInputHost", "ShellHost",
            "steam", "steamservice", "GameOverlayUI", "gameoverlayui64",
            "vgc", "vgtray", "EasyAntiCheat", "BEService", "FACEIT", "faceitclient",
            "agy", "WindowsTerminal", "powershell", "conhost", "SysPulse", "PerformansOdagi", "GameOptimizer"
        };

        // Work, Coding, Design & Engineering Apps (Boosted in Performance Mode, Protected from Kill)
        private readonly Dictionary<string, string> KnownWorkApps = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Code", "VS Code" },
            { "devenv", "Visual Studio" },
            { "rider64", "JetBrains Rider" },
            { "idea64", "IntelliJ IDEA" },
            { "pycharm64", "PyCharm" },
            { "studio64", "Android Studio" },
            { "blender", "Blender 3D" },
            { "Photoshop", "Adobe Photoshop" },
            { "AfterFX", "Adobe After Effects" },
            { "Adobe Premiere Pro", "Adobe Premiere Pro" },
            { "Illustrator", "Adobe Illustrator" },
            { "Resolve", "DaVinci Resolve" },
            { "acad", "AutoCAD" },
            { "SLDWORKS", "SolidWorks" },
            { "Unity", "Unity Editor" },
            { "UnrealEditor", "Unreal Engine" },
            { "MATLAB", "MATLAB" },
            { "WINWORD", "Microsoft Word" },
            { "EXCEL", "Microsoft Excel" },
            { "POWERPNT", "Microsoft PowerPoint" },
            { "Figma", "Figma" },
            { "Obsidian", "Obsidian" }
        };

        // Games (Boosted in Performance Mode, Protected from Kill)
        private readonly Dictionary<string, string> KnownGames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "cs2", "Counter-Strike 2" },
            { "VALORANT-Win64-Shipping", "VALORANT" },
            { "dota2", "Dota 2" },
            { "r5apex", "Apex Legends" },
            { "FortniteClient-Win64-Shipping", "Fortnite" },
            { "GTA5", "Grand Theft Auto V" },
            { "RustClient", "Rust" },
            { "eldenring", "Elden Ring" },
            { "Cyberpunk2077", "Cyberpunk 2077" },
            { "bf2042", "Battlefield 2042" },
            { "Overwatch", "Overwatch 2" },
            { "TslGame", "PUBG" },
            { "cod", "Call of Duty" },
            { "RainbowSix", "Rainbow Six Siege" },
            { "Deadlock", "Deadlock" },
            { "League of Legends", "League of Legends" },
            { "Minecraft.Windows", "Minecraft" },
            { "javaw", "Java / Minecraft" }
        };

        // Browsers (Can be placed into EcoQoS efficiency mode during Battery/Web mode)
        private readonly HashSet<string> BrowserProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi"
        };

        // Target Cleanup Categories
        private readonly string[] CatWindowsBloat = new[]
        {
            "PhoneExperienceHost", "CrossDeviceService", "CrossDeviceResume",
            "WidgetBoard", "WidgetService", "Widgets", "MicrosoftStartFeedProvider",
            "SearchHost", "YourPhone", "OneDrive", "Cortana", "SkypeApp", "GameBarPresenceWriter"
        };

        private readonly string[] CatGameOverlays = new[]
        {
            "GameBar", "XboxGameBarWidgets", "XboxGameBarSpotify", "GameBarFTServer",
            "XboxPcAppFT", "XboxPcApp", "XboxAppServices", "NVIDIA Overlay", "NVIDIA Share"
        };

        private readonly string[] CatIdleLaunchers = new[]
        {
            "SpotifyLauncher", "hamachi-2", "LMIGuardianSvc", "EpicGamesLauncher",
            "EpicWebHelper", "EA", "EADesktop", "EABackgroundService", "UbisoftConnect", "upc", "Battle.net"
        };

        // Detected Hardware Info
        private string sysVendor = "Genel PC";
        private string sysModel = "Windows Sistem";
        private string sysCpu = "İşlemci";
        private string sysGpu = "Ekran Kartı";
        private bool hasBattery = false;
        private bool lastOnBattery = false;
        private string currentModeName = "Standart / Dengeli";

        // Power Plan GUIDs discovered on this machine
        private string guidPowerSaver = null;
        private string guidBalanced = null;
        private string guidHighPerf = null;

        // SECURITY: user's original power scheme + processor-limit values, restored on Normal Mode / exit
        private string originalSchemeGuid = null;
        private readonly Dictionary<string, int[]> throttleBackup = new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase);

        // SECURITY: only revert what WE changed (services we stopped, processes we throttled)
        private readonly List<string> servicesStoppedByUs = new List<string>();
        private readonly Dictionary<int, ProcessPriorityClass> throttledByUs = new Dictionary<int, ProcessPriorityClass>();
        private readonly object stateLock = new object();

        // SECURITY: absolute System32 path -> no PATH / current-dir hijack of powercfg.exe
        private static readonly string PowerCfgPath = Path.Combine(Environment.SystemDirectory, "powercfg.exe");
        private static readonly Regex GuidRx = new Regex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z");
        private static readonly Regex SafePowerCfgArgsRx = new Regex(
            @"^(/list|/getactivescheme|/setactive [0-9a-fA-F-]{36}|/q(uery)? [0-9a-fA-F-]{36} SUB_PROCESSOR PROCTHROTTLEMAX|/set(ac|dc)valueindex [0-9a-fA-F-]{36} SUB_PROCESSOR PROCTHROTTLEMAX (100|[1-9][0-9]?))\z");

        // UI Controls
        private Label lblRamPercent;
        private Label lblRamDetail;
        private Label lblFreeRam;
        private Label lblActiveFocus;
        private Label lblSystemSummary;
        private Label lblPowerStatus;
        private Label lblProtectedTools;
        private Panel barRamFill;
        private Panel barRamBg;

        private CheckBox chkWinBloat;
        private CheckBox chkGameOverlays;
        private CheckBox chkLaunchers;
        private CheckBox chkHeavyServices;
        private CheckBox chkBrowserEco;
        private CheckBox chkStandbyPurge;
        private CheckBox chkAutoFocusBoost;
        private CheckBox chkAutoBatteryEco;

        private Button btnPerformanceFocus;
        private Button btnBatteryEcoFocus;
        private Button btnCleanRam;
        private Button btnRestoreNormal;
        private RichTextBox txtLog;
        private System.Windows.Forms.Timer uiTimer;
        private NotifyIcon trayIcon;

        private bool isBusy = false;
        private HashSet<int> boostedPids = new HashSet<int>();

        public MainForm()
        {
            InitializeUI();
            CheckAdminStatus();
            UpdateDashboardStats();

            this.Shown += async (s, e) =>
            {
                try
                {
                    int dark = 1;
                    NativeMethods.DwmSetWindowAttribute(this.Handle, 20, ref dark, sizeof(int));
                }
                catch { }
                this.Activate();
                await LoadHardwareProfileAsync();
            };

            uiTimer = new System.Windows.Forms.Timer { Interval = 2500 };
            uiTimer.Tick += (s, e) => OnTimerTick();
            uiTimer.Start();
        }

        private async Task LoadHardwareProfileAsync()
        {
            List<string> detectedTools = null;
            await Task.Run(() =>
            {
                DetectSystemHardwareAndPowerPlans();
                detectedTools = GetDetectedProtectedTools();
            });

            if (this.IsDisposed) return;
            lblSystemSummary.Text = string.Format("💻 Sistem: {0} {1} | İşlemci: {2}", sysVendor, sysModel, sysCpu);
            lblProtectedTools.Text = "🛡️ Otomatik Donanım Koruması: " + string.Join(", ", detectedTools);
            UpdateDashboardStats();
            Log(string.Format("Sistem algılandı: {0} {1} ({2})", sysVendor, sysModel, sysGpu), Color.FromArgb(100, 220, 255));
            Log("Korunan donanım araçları: " + string.Join(", ", detectedTools), Color.FromArgb(140, 210, 250));
        }

        private void DetectSystemHardwareAndPowerPlans()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        sysVendor = (obj["Manufacturer"] ?? "Genel").ToString().Trim();
                        sysModel = (obj["Model"] ?? "Bilgisayar").ToString().Trim();
                        break;
                    }
                }
            }
            catch { }

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        sysCpu = (obj["Name"] ?? "CPU").ToString().Trim();
                        sysCpu = Regex.Replace(sysCpu, @"\s+", " ");
                        break;
                    }
                }
            }
            catch { }

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController"))
                {
                    List<string> gpus = new List<string>();
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string g = (obj["Name"] ?? "").ToString().Trim();
                        if (!string.IsNullOrEmpty(g)) gpus.Add(g);
                    }
                    if (gpus.Count > 0) sysGpu = string.Join(" + ", gpus.Take(2));
                }
            }
            catch { }

            // Check battery status
            PowerStatus ps = SystemInformation.PowerStatus;
            hasBattery = (ps.BatteryChargeStatus & BatteryChargeStatus.NoSystemBattery) == 0;
            lastOnBattery = hasBattery && (ps.PowerLineStatus == PowerLineStatus.Offline);

            // Discover Power Plan GUIDs dynamically for any Windows language/OEM
            try
            {
                string output = RunPowerCfgCapture("/list");
                {
                    Regex rx = new Regex(@"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s+\(([^)]+)\)");
                    foreach (Match m in rx.Matches(output))
                    {
                        string guid = m.Groups[1].Value;
                        string name = m.Groups[2].Value.ToLowerInvariant();

                        if (name.Contains("saver") || name.Contains("tasarruf") || name.Contains("eco") || name.Contains("pil"))
                        {
                            if (guidPowerSaver == null) guidPowerSaver = guid;
                        }
                        else if (name.Contains("balanced") || name.Contains("dengeli"))
                        {
                            if (guidBalanced == null) guidBalanced = guid;
                        }
                        else if (name.Contains("high") || name.Contains("yüksek") || name.Contains("nihai") || name.Contains("ultimate") || name.Contains("turbo"))
                        {
                            if (guidHighPerf == null || name.Contains("high") || name.Contains("yüksek"))
                                guidHighPerf = guid;
                        }
                    }
                }

                // Remember user's currently active plan so Normal Mode returns to IT (not a hardcoded "Balanced")
                Match act = Regex.Match(RunPowerCfgCapture("/getactivescheme"), @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
                if (act.Success) originalSchemeGuid = act.Value;
            }
            catch { }

            // Standard Windows fallbacks if not parsed
            if (guidBalanced == null) guidBalanced = "381b4222-f694-41f0-9685-ff5bb260df2e";
            if (guidPowerSaver == null) guidPowerSaver = "a1841308-3541-4fab-bc81-f71556f20b4a";
            if (guidHighPerf == null) guidHighPerf = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
            if (originalSchemeGuid == null) originalSchemeGuid = guidBalanced;
        }

        private List<string> GetDetectedProtectedTools()
        {
            HashSet<string> detectedLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                Process[] procs = Process.GetProcesses();
                foreach (Process p in procs)
                {
                    try
                    {
                        string label;
                        if (OemProcessCatalog.TryGetValue(p.ProcessName, out label))
                        {
                            detectedLabels.Add(label);
                        }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }

            if (detectedLabels.Count == 0)
            {
                detectedLabels.Add("Sistem & Ekran Sürücüleri");
            }
            return detectedLabels.ToList();
        }

        private void InitializeUI()
        {
            this.Text = "SysPulse - Akıllı Sistem, Pil ve Bellek Yöneticisi";
            this.Size = new Size(800, 680);
            this.MinimumSize = new Size(800, 680);
            this.MaximumSize = new Size(800, 680);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.BackColor = Color.FromArgb(15, 18, 24);
            this.ForeColor = Color.FromArgb(235, 238, 245);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);
            try
            {
                this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch
            {
                this.Icon = SystemIcons.Shield;
            }

            // 1. Header & Adaptive System Dashboard Panel
            Panel pnlHeader = new Panel
            {
                Location = new Point(20, 14),
                Size = new Size(744, 142),
                BackColor = Color.FromArgb(24, 28, 38)
            };
            this.Controls.Add(pnlHeader);

            Label lblTitle = new Label
            {
                Text = "⚡ SYSPULSE",
                Font = new Font("Segoe UI", 13.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 212, 255),
                Location = new Point(18, 10),
                AutoSize = true
            };
            pnlHeader.Controls.Add(lblTitle);

            Label lblSubtitle = new Label
            {
                Text = "Akıllı Bellek, Pil Tasarrufu & İş/Oyun Hızlandırıcı",
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(145, 160, 185),
                Location = new Point(165, 15),
                AutoSize = true
            };
            pnlHeader.Controls.Add(lblSubtitle);

            lblActiveFocus = new Label
            {
                Text = "Durum: Sistem İzleniyor",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(110, 235, 150),
                Location = new Point(460, 13),
                Size = new Size(268, 22),
                TextAlign = ContentAlignment.TopRight
            };
            pnlHeader.Controls.Add(lblActiveFocus);

            lblRamPercent = new Label
            {
                Text = "%0",
                Font = new Font("Segoe UI", 22f, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(16, 40),
                Size = new Size(95, 42)
            };
            pnlHeader.Controls.Add(lblRamPercent);

            lblRamDetail = new Label
            {
                Text = "Kullanılan: 0.0 GB / 16.0 GB",
                Font = new Font("Segoe UI", 9.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(185, 195, 210),
                Location = new Point(115, 42),
                AutoSize = true
            };
            pnlHeader.Controls.Add(lblRamDetail);

            lblFreeRam = new Label
            {
                Text = "Boş RAM: 0.0 GB",
                Font = new Font("Segoe UI", 10.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(80, 225, 135),
                Location = new Point(115, 63),
                AutoSize = true
            };
            pnlHeader.Controls.Add(lblFreeRam);

            barRamBg = new Panel
            {
                Location = new Point(375, 48),
                Size = new Size(350, 20),
                BackColor = Color.FromArgb(38, 44, 58)
            };
            pnlHeader.Controls.Add(barRamBg);

            barRamFill = new Panel
            {
                Location = new Point(0, 0),
                Size = new Size(100, 20),
                BackColor = Color.FromArgb(0, 185, 240)
            };
            barRamBg.Controls.Add(barRamFill);

            lblPowerStatus = new Label
            {
                Text = "🔌 Güç Durumu: Algılanıyor...",
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 210, 100),
                Location = new Point(375, 73),
                Size = new Size(350, 20)
            };
            pnlHeader.Controls.Add(lblPowerStatus);

            // Adaptive Hardware Row at bottom of Header
            Panel pnlHwStrip = new Panel
            {
                Location = new Point(0, 98),
                Size = new Size(744, 44),
                BackColor = Color.FromArgb(19, 23, 31)
            };
            pnlHeader.Controls.Add(pnlHwStrip);

            lblSystemSummary = new Label
            {
                Text = "💻 Sistem donanımı taranıyor...",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(175, 190, 210),
                Location = new Point(16, 4),
                AutoSize = true
            };
            pnlHwStrip.Controls.Add(lblSystemSummary);

            lblProtectedTools = new Label
            {
                Text = "🛡️ Otomatik Donanım Koruması: Taranıyor...",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Italic),
                ForeColor = Color.FromArgb(110, 210, 250),
                Location = new Point(16, 22),
                AutoSize = true
            };
            pnlHwStrip.Controls.Add(lblProtectedTools);

            // 2. Options Panel
            Panel pnlOptions = new Panel
            {
                Location = new Point(20, 168),
                Size = new Size(744, 198),
                BackColor = Color.FromArgb(24, 28, 38)
            };
            this.Controls.Add(pnlOptions);

            Label lblOptHeader = new Label
            {
                Text = "AKILLI OPTİMİZASYON & KAYNAK KORUMA SEÇENEKLERİ",
                Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(145, 165, 195),
                Location = new Point(18, 10),
                AutoSize = true
            };
            pnlOptions.Controls.Add(lblOptHeader);

            chkWinBloat = CreateCheck(pnlOptions, 18, 35, true,
                "Windows Gereksiz Arka Plan (Telefon Bağlantısı, Widgets, Hava Durumu, Copilot/Arama Önbelleği)");
            chkLaunchers = CreateCheck(pnlOptions, 18, 61, true,
                "Arka Plan Mağaza & Başlatıcıları Hafiflet (Steam WebHelper, Epic, EA, SpotifyLauncher, Hamachi)");
            chkGameOverlays = CreateCheck(pnlOptions, 18, 87, true,
                "Gereksiz Xbox Game Bar & Arka Plan Kayıt Katmanlarını Kapat (~300 MB RAM & Pil tasarrufu)");
            chkHeavyServices = CreateCheck(pnlOptions, 18, 113, true,
                "Boştaki Ağır Servisleri Duraklat (Kullanılmayan WSL / Hyper-V / Hamachi - yazıcı servisine dokunulmaz)");
            chkBrowserEco = CreateCheck(pnlOptions, 18, 139, true,
                "Pil/Web Modunda Tarayıcıları (Chrome/Edge/Firefox/Brave) Windows Verimlilik Moduna (EcoQoS) Al");
            chkStandbyPurge = CreateCheck(pnlOptions, 18, 165, true,
                "Derin RAM Sıkıştırma & Windows Standby (Bekleme) Önbelleği Temizliği");

            // Right-side Smart Automation Toggles
            chkAutoFocusBoost = CreateCheck(pnlOptions, 465, 139, true,
                "Otomatik İş / Oyun CPU Hızlandırma");
            chkAutoBatteryEco = CreateCheck(pnlOptions, 465, 165, true,
                "Pildeyken Otomatik Güç Tasarrufu");

            // 3. Action Buttons (4 Modes)
            btnPerformanceFocus = CreateButton("⚡ PERFORMANS ODAĞI BAŞLAT", new Point(20, 378), new Size(235, 52),
                Color.FromArgb(0, 150, 105), Color.White);
            btnPerformanceFocus.Click += async (s, e) => await RunPerformanceFocusAsync();
            this.Controls.Add(btnPerformanceFocus);

            btnBatteryEcoFocus = CreateButton("🔋 PİL & WEB TASARRUF MODU", new Point(265, 378), new Size(225, 52),
                Color.FromArgb(205, 125, 20), Color.White);
            btnBatteryEcoFocus.Click += async (s, e) => await RunBatteryEcoModeAsync(autoTriggered: false);
            this.Controls.Add(btnBatteryEcoFocus);

            btnCleanRam = CreateButton("🧹 BELLEK TEMİZLE", new Point(500, 378), new Size(145, 52),
                Color.FromArgb(0, 115, 195), Color.White);
            btnCleanRam.Click += async (s, e) => await RunCleanMemoryOnlyAsync();
            this.Controls.Add(btnCleanRam);

            btnRestoreNormal = CreateButton("🔄 NORMAL MOD", new Point(655, 378), new Size(109, 52),
                Color.FromArgb(55, 62, 78), Color.FromArgb(225, 230, 240));
            btnRestoreNormal.Click += async (s, e) => await RestoreNormalModeAsync();
            this.Controls.Add(btnRestoreNormal);

            // 4. Activity Log Box
            txtLog = new RichTextBox
            {
                Location = new Point(20, 442),
                Size = new Size(744, 182),
                BackColor = Color.FromArgb(11, 13, 18),
                ForeColor = Color.FromArgb(200, 215, 230),
                Font = new Font("Consolas", 9.1f, FontStyle.Regular),
                ReadOnly = true,
                BorderStyle = BorderStyle.None
            };
            this.Controls.Add(txtLog);

            // 5. System Tray Icon & Context Menu
            trayIcon = new NotifyIcon
            {
                Icon = this.Icon ?? SystemIcons.Shield,
                Text = "SysPulse - Sistem & Pil Yöneticisi",
                Visible = true
            };
            ContextMenuStrip trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("Pencereyi Aç", null, (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.Activate(); });
            trayMenu.Items.Add("⚡ Performans Odağı Başlat", null, async (s, e) => await RunPerformanceFocusAsync());
            trayMenu.Items.Add("🔋 Pil & Web Tasarruf Modu", null, async (s, e) => await RunBatteryEcoModeAsync(false));
            trayMenu.Items.Add("🧹 Bellek Temizle", null, async (s, e) => await RunCleanMemoryOnlyAsync());
            trayMenu.Items.Add("🔄 Normal Mod", null, async (s, e) => await RestoreNormalModeAsync());
            trayMenu.Items.Add("-");
            trayMenu.Items.Add("Çıkış", null, (s, e) => { trayIcon.Visible = false; Application.Exit(); });
            trayIcon.ContextMenuStrip = trayMenu;
            trayIcon.DoubleClick += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.Activate(); };
        }

        private CheckBox CreateCheck(Control parent, int x, int y, bool isChecked, string text)
        {
            CheckBox chk = new CheckBox
            {
                Location = new Point(x, y),
                Text = text,
                Checked = isChecked,
                AutoSize = true,
                ForeColor = Color.FromArgb(220, 225, 235),
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            parent.Controls.Add(chk);
            return chk;
        }

        private Button CreateButton(string text, Point loc, Size size, Color backColor, Color foreColor)
        {
            Button btn = new Button
            {
                Text = text,
                Location = loc,
                Size = size,
                BackColor = backColor,
                ForeColor = foreColor,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 0;
            return btn;
        }

        private void CheckAdminStatus()
        {
            bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            if (isAdmin)
            {
                Log("[✓] Yönetici yetkisi aktif: Derin Bellek, EcoQoS Pil Tasarrufu ve Güç Planı kontrolü hazır.", Color.FromArgb(110, 230, 140));
            }
            else
            {
                Log("[!] Not: Tam Standby RAM ve servis kontrolü için uygulamayı Yönetici olarak çalıştırabilirsiniz.", Color.FromArgb(255, 200, 90));
            }
        }

        private async void OnTimerTick()
        {
            UpdateDashboardStats();

            if (isBusy) return;

            // Check automatic battery transition
            PowerStatus ps = SystemInformation.PowerStatus;
            bool nowOnBattery = hasBattery && (ps.PowerLineStatus == PowerLineStatus.Offline);
            if (nowOnBattery && !lastOnBattery && chkAutoBatteryEco.Checked)
            {
                lastOnBattery = true;
                Log("[🔋] Bilgisayar fişten çekildi (Pilde). Otomatik Pil & Web Tasarruf Modu devreye alınıyor...", Color.FromArgb(255, 200, 80));
                await RunBatteryEcoModeAsync(autoTriggered: true);
                return;
            }
            lastOnBattery = nowOnBattery;

            if (chkAutoFocusBoost.Checked && !nowOnBattery)
            {
                CheckAndBoostActiveFocusApps(silent: true);
            }
            else
            {
                UpdateActiveFocusLabelOnly();
            }
        }

        private struct MemoryInfo
        {
            public double totalGb;
            public double usedGb;
            public double freeGb;
            public uint loadPct;
        }

        private MemoryInfo GetMemoryInfo()
        {
            NativeMethods.MEMORYSTATUSEX mem = new NativeMethods.MEMORYSTATUSEX();
            if (NativeMethods.GlobalMemoryStatusEx(mem))
            {
                double total = mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
                double free = mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0);
                double used = total - free;
                return new MemoryInfo { totalGb = total, usedGb = used, freeGb = free, loadPct = mem.dwMemoryLoad };
            }
            return new MemoryInfo { totalGb = 16.0, usedGb = 8.0, freeGb = 8.0, loadPct = 50 };
        }

        private void UpdateDashboardStats()
        {
            var info = GetMemoryInfo();
            lblRamPercent.Text = "%" + info.loadPct;
            lblRamDetail.Text = string.Format("Kullanılan: {0:0.00} GB / {1:0.00} GB", info.usedGb, info.totalGb);
            lblFreeRam.Text = string.Format("Boş RAM: {0:0.00} GB ({1:0} MB)", info.freeGb, info.freeGb * 1024.0);

            int fillWidth = (int)Math.Round((info.loadPct / 100.0) * barRamBg.Width);
            barRamFill.Width = Math.Max(4, Math.Min(barRamBg.Width, fillWidth));

            if (info.loadPct >= 80)
                barRamFill.BackColor = Color.FromArgb(235, 75, 75);
            else if (info.loadPct >= 65)
                barRamFill.BackColor = Color.FromArgb(245, 170, 50);
            else
                barRamFill.BackColor = Color.FromArgb(40, 205, 130);

            // Power & Battery Status
            PowerStatus ps = SystemInformation.PowerStatus;
            hasBattery = (ps.BatteryChargeStatus & BatteryChargeStatus.NoSystemBattery) == 0;
            if (!hasBattery)
            {
                lblPowerStatus.Text = string.Format("🖥️ Masaüstü Güç (AC) | Aktif Mod: {0}", currentModeName);
                lblPowerStatus.ForeColor = Color.FromArgb(140, 215, 255);
            }
            else
            {
                int pct = (int)Math.Round(ps.BatteryLifePercent * 100.0);
                bool onBattery = (ps.PowerLineStatus == PowerLineStatus.Offline);
                if (onBattery)
                {
                    string rem = ps.BatteryLifeRemaining > 0
                        ? string.Format(" (~{0} dk)", ps.BatteryLifeRemaining / 60)
                        : "";
                    lblPowerStatus.Text = string.Format("🔋 Pilde Çalışıyor: %{0}{1} | Mod: {2}", pct, rem, currentModeName);
                    lblPowerStatus.ForeColor = Color.FromArgb(255, 195, 75);
                }
                else
                {
                    lblPowerStatus.Text = string.Format("🔌 Fişte / Şarjda (%{0}) | Mod: {1}", pct, currentModeName);
                    lblPowerStatus.ForeColor = Color.FromArgb(115, 235, 155);
                }
            }
        }

        private bool IsProcessWhitelisted(string procName)
        {
            return CoreSystemWhitelist.Contains(procName) ||
                   OemProcessCatalog.ContainsKey(procName) ||
                   KnownGames.ContainsKey(procName) ||
                   KnownWorkApps.ContainsKey(procName);
        }

        private void UpdateActiveFocusLabelOnly()
        {
            string detectedFocus = DetectRunningFocusLabel();
            if (detectedFocus != null)
            {
                lblActiveFocus.Text = "🎯 Odak: " + detectedFocus;
                lblActiveFocus.ForeColor = Color.FromArgb(110, 240, 150);
            }
            else
            {
                lblActiveFocus.Text = "Durum: Günlük / Web Kullanımı";
                lblActiveFocus.ForeColor = Color.FromArgb(165, 180, 200);
            }
        }

        private string DetectRunningFocusLabel()
        {
            Process[] all = Process.GetProcesses();
            string foundWork = null;
            string foundGame = null;
            foreach (Process p in all)
            {
                try
                {
                    string label;
                    if (foundGame == null && KnownGames.TryGetValue(p.ProcessName, out label))
                        foundGame = label + " (Oyun)";
                    else if (foundWork == null && KnownWorkApps.TryGetValue(p.ProcessName, out label))
                        foundWork = label + " (İş/Üretim)";
                }
                catch { }
                finally { p.Dispose(); }
            }
            return foundGame ?? foundWork;
        }

        private int CheckAndBoostActiveFocusApps(bool silent)
        {
            int count = 0;
            string activeLabel = null;

            Process[] allProcs = Process.GetProcesses();
            foreach (Process p in allProcs)
            {
                try
                {
                    string friendlyName = null;
                    bool isGame = KnownGames.TryGetValue(p.ProcessName, out friendlyName);
                    bool isWork = !isGame && KnownWorkApps.TryGetValue(p.ProcessName, out friendlyName);

                    if (isGame || isWork)
                    {
                        activeLabel = friendlyName;
                        ProcessPriorityClass targetPriority = isGame ? ProcessPriorityClass.High : ProcessPriorityClass.AboveNormal;

                        if (p.PriorityClass != targetPriority && p.PriorityClass != ProcessPriorityClass.High)
                        {
                            NativeMethods.SetProcessEcoQoS(p.Handle, enableEco: false);
                            p.PriorityClass = targetPriority;
                            count++;
                            if (!boostedPids.Contains(p.Id))
                            {
                                boostedPids.Add(p.Id);
                                Log(string.Format("[⚡] Performans Odağı: {0} ({1}.exe) -> İşlemci önceliği yükseltildi.",
                                    friendlyName, p.ProcessName), Color.FromArgb(120, 240, 150));
                            }
                        }
                        else if (!silent)
                        {
                            Log(string.Format("[✓] {0} ({1}.exe) yüksek performans önceliğinde çalışıyor.",
                                friendlyName, p.ProcessName), Color.FromArgb(120, 240, 150));
                        }
                    }
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }

            if (activeLabel != null)
            {
                lblActiveFocus.Text = "⚡ Aktif Odak: " + activeLabel;
                lblActiveFocus.ForeColor = Color.FromArgb(100, 240, 140);
            }
            else
            {
                lblActiveFocus.Text = "Durum: Günlük / Web Kullanımı";
                lblActiveFocus.ForeColor = Color.FromArgb(165, 180, 200);
            }

            return count;
        }

        // MODE 1: PERFORMANS ODAĞI (Yüksek Performans - İş, Üretim & Oyun)
        private async Task RunPerformanceFocusAsync()
        {
            if (isBusy) return;
            isBusy = true;
            SetButtonsEnabled(false);

            var beforeMem = GetMemoryInfo();
            currentModeName = "⚡ SYSPULSE";
            Log("----------------------------------------------------------------------", Color.FromArgb(90, 100, 120));
            Log("⚡ PERFORMANS ODAĞI BAŞLATILIYOR (İş, Üretim ve Oyun Hızlandırma)...", Color.FromArgb(0, 212, 255));

            int killedCount = 0;
            int trimmedProcs = 0;
            bool standbyOk = false;

            bool doWinBloat = chkWinBloat.Checked;
            bool doOverlays = chkGameOverlays.Checked;
            bool doLaunchers = chkLaunchers.Checked;
            bool doServices = chkHeavyServices.Checked;
            bool doStandby = chkStandbyPurge.Checked;

            await Task.Run(() =>
            {
                CleanupBackgroundProcesses(doWinBloat, doOverlays, doLaunchers, doServices, false, ref killedCount);

                // Restore full speed to browsers if WE throttled them earlier (Eco mode)
                RestoreThrottledProcesses();

                // Activate High Performance plan & 100% AC CPU state (original values backed up first)
                ApplyPowerPlan(guidHighPerf, 100, null);

                Thread.Sleep(350);
                trimmedProcs = TrimAllWorkingSets();

                if (doStandby)
                {
                    NativeMethods.PurgeStandbyMemory(out standbyOk);
                }
            });

            CheckAndBoostActiveFocusApps(silent: false);
            UpdateDashboardStats();

            var afterMem = GetMemoryInfo();
            double gainedMb = Math.Max(0, (afterMem.freeGb - beforeMem.freeGb) * 1024.0);

            Log(string.Format("[✓] {0} gereksiz arka plan işlemi kapatıldı, {1} işlemin belleği optimize edildi.", killedCount, trimmedProcs), Color.FromArgb(110, 235, 150));
            Log(string.Format("✨ PERFORMANS ODAĞI AKTİF: Boş RAM {0:0.00} GB -> {1:0.00} GB (+{2:0} MB Kazanç)",
                beforeMem.freeGb, afterMem.freeGb, gainedMb), Color.FromArgb(80, 255, 160));

            SetButtonsEnabled(true);
            isBusy = false;
        }

        // MODE 2: PİL & WEB TASARRUF MODU (Eko Odak - Laptop / Web Gezinme / Ofis)
        private async Task RunBatteryEcoModeAsync(bool autoTriggered)
        {
            if (isBusy) return;
            isBusy = true;
            SetButtonsEnabled(false);

            var beforeMem = GetMemoryInfo();
            currentModeName = "🔋 Pil & Web Tasarrufu";
            Log("----------------------------------------------------------------------", Color.FromArgb(90, 100, 120));
            Log("🔋 PİL & WEB TASARRUF MODU BAŞLATILIYOR (Gereksiz Tüketim Engelleniyor)...", Color.FromArgb(255, 200, 80));

            int killedCount = 0;
            int ecoThrottledCount = 0;
            int trimmedProcs = 0;
            bool standbyOk = false;

            bool doWinBloat = chkWinBloat.Checked;
            bool doOverlays = chkGameOverlays.Checked;
            bool doLaunchers = chkLaunchers.Checked;
            bool doServices = chkHeavyServices.Checked;
            bool doBrowserEco = chkBrowserEco.Checked;
            bool doStandby = chkStandbyPurge.Checked;

            await Task.Run(() =>
            {
                // Detect if any game is actually running right now; if not, we can also close idle game helpers
                bool anyGameRunning = DetectRunningGame();
                CleanupBackgroundProcesses(doWinBloat, doOverlays, doLaunchers, doServices, !anyGameRunning, ref killedCount);

                // Put background processes & heavy multi-tab browser sub-processes into Windows Efficiency Mode (EcoQoS)
                Process[] allProcs = Process.GetProcesses();
                foreach (Process p in allProcs)
                {
                    try
                    {
                        string name = p.ProcessName;
                        // SECURITY: same safety gate as kill -> never throttle OS (System32), services (session 0), protected/OEM/work/game apps
                        if (!IsSafeToKill(p))
                            continue;

                        bool isBrowser = BrowserProcesses.Contains(name);
                        if (isBrowser && doBrowserEco)
                        {
                            // Keep main foreground browser window responsive, throttle background renderer tabs
                            if (p.MainWindowHandle == IntPtr.Zero)
                            {
                                if (ThrottleProcess(p))
                                    ecoThrottledCount++;
                            }
                        }
                        else if (!isBrowser)
                        {
                            // Throttle non-critical background user processes so they don't spike CPU turbo on battery
                            if (p.MainWindowHandle == IntPtr.Zero)
                            {
                                if (ThrottleProcess(p))
                                    ecoThrottledCount++;
                            }
                        }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }

                // Switch to Power Saver & cap DC processor state to 85% (original values backed up, restored in Normal Mode)
                ApplyPowerPlan(guidPowerSaver, null, 85);

                Thread.Sleep(350);
                trimmedProcs = TrimAllWorkingSets();

                if (doStandby)
                {
                    NativeMethods.PurgeStandbyMemory(out standbyOk);
                }
            });

            UpdateDashboardStats();
            var afterMem = GetMemoryInfo();
            double gainedMb = Math.Max(0, (afterMem.freeGb - beforeMem.freeGb) * 1024.0);

            Log(string.Format("[🔋] {0} pil tüketen arka plan uygulaması kapatıldı, {1} işlem Verimlilik Moduna (EcoQoS) alındı.",
                killedCount, ecoThrottledCount), Color.FromArgb(255, 215, 110));
            Log("[🔋] Güç Tasarrufu planı etkinleştirildi ve pilde gereksiz işlemci Turbo Boost sıçramaları sınırlandı.", Color.FromArgb(255, 215, 110));
            Log(string.Format("✨ PİL & WEB MODU AKTİF: Boş RAM {0:0.00} GB -> {1:0.00} GB (+{2:0} MB RAM Kazanç)",
                beforeMem.freeGb, afterMem.freeGb, gainedMb), Color.FromArgb(100, 245, 165));

            SetButtonsEnabled(true);
            isBusy = false;
        }

        // MODE 3: SADECE BELLEK TEMİZLEME
        private async Task RunCleanMemoryOnlyAsync()
        {
            if (isBusy) return;
            isBusy = true;
            SetButtonsEnabled(false);

            var beforeMem = GetMemoryInfo();
            Log("----------------------------------------------------------------------", Color.FromArgb(90, 100, 120));
            Log("🧹 HIZLI BELLEK (RAM) TEMİZLEME BAŞLATILIYOR...", Color.FromArgb(0, 212, 255));

            int trimmedProcs = 0;
            bool standbyOk = false;
            bool doStandby = chkStandbyPurge.Checked;

            await Task.Run(() =>
            {
                trimmedProcs = TrimAllWorkingSets();
                if (doStandby)
                {
                    NativeMethods.PurgeStandbyMemory(out standbyOk);
                }
            });

            UpdateDashboardStats();
            var afterMem = GetMemoryInfo();
            double gainedMb = Math.Max(0, (afterMem.freeGb - beforeMem.freeGb) * 1024.0);

            Log(string.Format("[✓] Hiçbir uygulama kapatılmadan {0} işlemin RAM çalışma kümesi temizlendi.", trimmedProcs), Color.FromArgb(110, 235, 150));
            if (standbyOk)
                Log("[✓] Windows Standby (Bekleme) önbelleği sıfırlandı.", Color.FromArgb(110, 235, 150));
            Log(string.Format("✨ BELLEK TEMİZLENDİ: Boş RAM {0:0.00} GB -> {1:0.00} GB (+{2:0} MB Açıldı)",
                beforeMem.freeGb, afterMem.freeGb, gainedMb), Color.FromArgb(80, 255, 160));

            SetButtonsEnabled(true);
            isBusy = false;
        }

        // MODE 4: NORMAL / DENGELİ MODA DÖNÜŞ
        private async Task RestoreNormalModeAsync()
        {
            if (isBusy) return;
            isBusy = true;
            SetButtonsEnabled(false);

            currentModeName = "Standart / Dengeli";
            Log("----------------------------------------------------------------------", Color.FromArgb(90, 100, 120));
            Log("🔄 Normal / Dengeli Moda dönülüyor...", Color.FromArgb(0, 212, 255));

            await Task.Run(() =>
            {
                // Restore user's ORIGINAL power plan + original processor-limit values (backed up before modification)
                RestorePowerPlans();

                // Restore EcoQoS/priority ONLY on processes SysPulse itself throttled
                RestoreThrottledProcesses();

                // Restart ONLY services SysPulse itself stopped
                RestartServicesStoppedByUs();
            });

            UpdateDashboardStats();
            Log("[✓] Orijinal güç planı, işlemci limitleri, uygulama öncelikleri ve durdurulan servisler geri yüklendi.", Color.FromArgb(110, 235, 150));

            SetButtonsEnabled(true);
            isBusy = false;
        }

        private bool DetectRunningGame()
        {
            Process[] all = Process.GetProcesses();
            bool found = false;
            foreach (Process p in all)
            {
                try
                {
                    if (KnownGames.ContainsKey(p.ProcessName)) found = true;
                }
                catch { }
                finally { p.Dispose(); }
            }
            return found;
        }

        private void CleanupBackgroundProcesses(bool doWinBloat, bool doOverlays, bool doLaunchers, bool doServices, bool closeIdleSteamCompletely, ref int killedCount)
        {
            HashSet<string> targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (doWinBloat) foreach (var t in CatWindowsBloat) targets.Add(t);
            if (doOverlays) foreach (var t in CatGameOverlays) targets.Add(t);
            if (doLaunchers) foreach (var t in CatIdleLaunchers) targets.Add(t);

            Process[] allProcs = Process.GetProcesses();
            foreach (Process p in allProcs)
            {
                try
                {
                    string name = p.ProcessName;
                    if (!targets.Contains(name))
                        continue;

                    // SECURITY: name match alone is not enough -> session / System32 / whitelist gate
                    // (msedgewebview2 blanket-kill REMOVED: it is shared by Teams, Outlook, Widgets, many apps -> data loss risk.
                    //  Widget/Search WebView2 children exit automatically when their host is closed.)
                    if (!IsSafeToKill(p))
                        continue;

                    long ws = 0;
                    try { ws = p.WorkingSet64; } catch { }
                    p.Kill();
                    killedCount++;
                    LogSafe(string.Format("  [-] Kapatıldı: {0}.exe ({1:0.0} MB RAM)", name, ws / (1024.0 * 1024.0)), Color.FromArgb(220, 185, 120));
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }

            if (doLaunchers)
            {
                // Steam overlay / friends depend on steamwebhelper while a game runs -> never kill during a game
                bool gameRunning = DetectRunningGame();
                Process[] steamHelpers = Process.GetProcessesByName("steamwebhelper");
                foreach (Process sh in steamHelpers)
                {
                    try
                    {
                        if (!IsSafeToKill(sh)) continue;
                        long ws = sh.WorkingSet64;
                        if (closeIdleSteamCompletely && !gameRunning && ws > 90 * 1024 * 1024)
                        {
                            sh.Kill();
                            killedCount++;
                            LogSafe(string.Format("  [-] Hafifletildi: steamwebhelper.exe ({0:0.0} MB RAM)", ws / (1024.0 * 1024.0)), Color.FromArgb(200, 180, 255));
                        }
                        else
                        {
                            ThrottleProcess(sh);
                        }
                    }
                    catch { }
                    finally { sh.Dispose(); }
                }
            }

            if (doServices)
            {
                // SECURITY: Spooler REMOVED (breaks printing; system-wide; was only restarted by name).
                // Each optional service is stopped ONLY if nothing is currently using it, and is tracked for restore.
                var optionalServices = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
                {
                    { "WslService",  new[] { "wsl", "wslhost", "wslservice", "vmmem", "vmmemWSL" } },  // running WSL distro -> keep
                    { "vmms",        new[] { "vmwp", "vmmem", "vmconnect" } },                          // running Hyper-V VM -> keep (data loss risk)
                    { "Hamachi2Svc", new[] { "hamachi-2-ui" } }                                         // VPN UI open -> keep
                };
                foreach (var kv in optionalServices)
                {
                    string svcName = kv.Key;
                    if (ProtectedServices.Contains(svcName)) continue; // defense in depth
                    try
                    {
                        bool inUse = kv.Value.Any(pn => { var ps = Process.GetProcessesByName(pn); bool any = ps.Length > 0; foreach (var x in ps) x.Dispose(); return any; });
                        if (inUse)
                        {
                            LogSafe(string.Format("  [i] {0} kullanımda, durdurulmadı.", svcName), Color.FromArgb(160, 175, 195));
                            continue;
                        }
                        using (ServiceController sc = new ServiceController(svcName))
                        {
                            if (sc.Status == ServiceControllerStatus.Running && sc.CanStop)
                            {
                                sc.Stop();
                                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                                lock (stateLock) { if (!servicesStoppedByUs.Contains(svcName)) servicesStoppedByUs.Add(svcName); }
                                LogSafe(string.Format("  [-] Boştaki servis duraklatıldı: {0}", svcName), Color.FromArgb(180, 195, 210));
                            }
                        }
                    }
                    catch { } // service not installed / no admin -> skip silently
                }
            }
        }

        // SECURITY: services that must never be stopped by this tool, regardless of future list edits
        private static readonly HashSet<string> ProtectedServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Spooler", "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "Winmgmt", "EventLog", "Dhcp", "Dnscache",
            "nsi", "BFE", "mpssvc", "WinDefend", "SecurityHealthService", "wscsvc", "CryptSvc", "Schedule",
            "AudioSrv", "AudioEndpointBuilder", "Power", "PlugPlay", "ProfSvc", "UserManager", "Themes",
            "wuauserv", "TrustedInstaller", "SamSs", "gpsvc", "LanmanWorkstation", "WlanSvc", "BrokerInfrastructure"
        };

        private int TrimAllWorkingSets()
        {
            int trimmed = 0;
            Process[] currentProcs = Process.GetProcesses();
            foreach (Process p in currentProcs)
            {
                try
                {
                    string name = p.ProcessName;
                    if (KnownGames.ContainsKey(name) ||
                        name.Equals("ResourceMonitorOSD", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("RTSS", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("dwm", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (NativeMethods.EmptyWorkingSet(p.Handle) != 0)
                    {
                        trimmed++;
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
            return trimmed;
        }

        private void RunPowerCfg(string args)
        {
            RunPowerCfgCapture(args);
        }

        // SECURITY: hardened powercfg runner
        //  - absolute System32 path (no PATH / app-folder hijack)
        //  - no shell (UseShellExecute=false -> no cmd.exe metacharacter interpretation)
        //  - strict allow-list regex on full argument string (no injected switches / extra args)
        private static string RunPowerCfgCapture(string args)
        {
            if (args == null || !SafePowerCfgArgsRx.IsMatch(args))
                return string.Empty;
            if (!File.Exists(PowerCfgPath))
                return string.Empty;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(PowerCfgPath, args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    StandardOutputEncoding = Encoding.Default,
                    WorkingDirectory = Environment.SystemDirectory
                };
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(3000);
                    return output ?? string.Empty;
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private static bool IsValidGuid(string g)
        {
            return g != null && GuidRx.IsMatch(g);
        }

        // Back up PROCTHROTTLEMAX (AC, DC) of a scheme once, before we modify it
        private void BackupThrottle(string guid)
        {
            if (!IsValidGuid(guid)) return;
            lock (stateLock)
            {
                if (throttleBackup.ContainsKey(guid)) return;
            }
            string q = RunPowerCfgCapture("/query " + guid + " SUB_PROCESSOR PROCTHROTTLEMAX");
            // Last two hex values in the output are AC and DC current indexes (language independent)
            MatchCollection hex = Regex.Matches(q, @"0x([0-9a-fA-F]{8})");
            if (hex.Count < 2) return;
            int ac = Convert.ToInt32(hex[hex.Count - 2].Groups[1].Value, 16);
            int dc = Convert.ToInt32(hex[hex.Count - 1].Groups[1].Value, 16);
            if (ac < 1 || ac > 100 || dc < 1 || dc > 100) return;
            lock (stateLock) { throttleBackup[guid] = new[] { ac, dc }; }
        }

        private void ApplyPowerPlan(string guid, int? acMax, int? dcMax)
        {
            if (!IsValidGuid(guid)) return;
            if (acMax.HasValue || dcMax.HasValue) BackupThrottle(guid);
            if (acMax.HasValue) RunPowerCfg("/setacvalueindex " + guid + " SUB_PROCESSOR PROCTHROTTLEMAX " + Math.Max(1, Math.Min(100, acMax.Value)));
            if (dcMax.HasValue) RunPowerCfg("/setdcvalueindex " + guid + " SUB_PROCESSOR PROCTHROTTLEMAX " + Math.Max(1, Math.Min(100, dcMax.Value)));
            RunPowerCfg("/setactive " + guid);
        }

        // Restore user's original values and original active plan
        private void RestorePowerPlans()
        {
            List<KeyValuePair<string, int[]>> items;
            lock (stateLock) { items = throttleBackup.ToList(); throttleBackup.Clear(); }
            foreach (var kv in items)
            {
                RunPowerCfg("/setacvalueindex " + kv.Key + " SUB_PROCESSOR PROCTHROTTLEMAX " + kv.Value[0]);
                RunPowerCfg("/setdcvalueindex " + kv.Key + " SUB_PROCESSOR PROCTHROTTLEMAX " + kv.Value[1]);
            }
            if (IsValidGuid(originalSchemeGuid)) RunPowerCfg("/setactive " + originalSchemeGuid);
        }

        // SECURITY: is it safe to terminate this process?
        //  - only processes in OUR interactive session (never session 0 services)
        //  - never binaries from System32 / SysWOW64 (core OS components)
        //  - never protected names
        private bool IsSafeToKill(Process p)
        {
            try
            {
                if (p.Id == Process.GetCurrentProcess().Id) return false;
                if (p.SessionId == 0 || p.SessionId != Process.GetCurrentProcess().SessionId) return false;
                if (IsProcessWhitelisted(p.ProcessName)) return false;

                string path = null;
                try { path = p.MainModule.FileName; } catch { }
                if (path != null)
                {
                    string sys32 = Environment.SystemDirectory.TrimEnd('\\') + "\\";
                    string wow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64") + "\\";
                    if (path.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
                        path.StartsWith(wow64, StringComparison.OrdinalIgnoreCase))
                        return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        // Throttle a process and remember its original priority so restore only touches what we changed
        private bool ThrottleProcess(Process p)
        {
            try
            {
                ProcessPriorityClass original = p.PriorityClass;
                bool eco = NativeMethods.SetProcessEcoQoS(p.Handle, enableEco: true);
                if (original == ProcessPriorityClass.Normal || original == ProcessPriorityClass.AboveNormal)
                    p.PriorityClass = ProcessPriorityClass.BelowNormal;
                lock (stateLock)
                {
                    if (!throttledByUs.ContainsKey(p.Id)) throttledByUs[p.Id] = original;
                }
                return eco;
            }
            catch
            {
                return false;
            }
        }

        private void RestoreThrottledProcesses()
        {
            List<KeyValuePair<int, ProcessPriorityClass>> items;
            lock (stateLock) { items = throttledByUs.ToList(); throttledByUs.Clear(); }
            foreach (var kv in items)
            {
                try
                {
                    using (Process p = Process.GetProcessById(kv.Key))
                    {
                        NativeMethods.SetProcessEcoQoS(p.Handle, enableEco: false);
                        if (p.PriorityClass == ProcessPriorityClass.BelowNormal)
                            p.PriorityClass = kv.Value;
                    }
                }
                catch { } // process exited -> nothing to restore
            }
        }

        private void RestartServicesStoppedByUs()
        {
            List<string> items;
            lock (stateLock) { items = servicesStoppedByUs.ToList(); servicesStoppedByUs.Clear(); }
            foreach (string svcName in items)
            {
                try
                {
                    using (ServiceController sc = new ServiceController(svcName))
                    {
                        if (sc.Status == ServiceControllerStatus.Stopped)
                        {
                            sc.Start();
                            LogSafe(string.Format("  [+] Servis tekrar başlatıldı: {0}", svcName), Color.FromArgb(130, 220, 150));
                        }
                    }
                }
                catch { }
            }
        }

        private void SetButtonsEnabled(bool enabled)
        {
            btnPerformanceFocus.Enabled = enabled;
            btnBatteryEcoFocus.Enabled = enabled;
            btnCleanRam.Enabled = enabled;
            btnRestoreNormal.Enabled = enabled;
        }

        private void LogSafe(string message, Color color)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(() => Log(message, color)));
            }
            else
            {
                Log(message, color);
            }
        }

        private void Log(string message, Color color)
        {
            string time = DateTime.Now.ToString("HH:mm:ss");
            txtLog.SelectionStart = txtLog.TextLength;
            txtLog.SelectionLength = 0;
            txtLog.SelectionColor = Color.FromArgb(120, 130, 150);
            txtLog.AppendText("[" + time + "] ");

            txtLog.SelectionStart = txtLog.TextLength;
            txtLog.SelectionLength = 0;
            txtLog.SelectionColor = color;
            txtLog.AppendText(message + Environment.NewLine);
            txtLog.ScrollToCaret();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // SAFETY: never leave the system in a modified state after exit
            try
            {
                bool dirty;
                lock (stateLock) { dirty = throttleBackup.Count > 0 || throttledByUs.Count > 0 || servicesStoppedByUs.Count > 0; }
                if (dirty)
                {
                    uiTimer.Stop();
                    RestorePowerPlans();
                    RestoreThrottledProcesses();
                    RestartServicesStoppedByUs();
                }
            }
            catch { }

            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }
            base.OnFormClosing(e);
        }
    }

    static class Program
    {
        // SECURITY: per-user log location (no hardcoded profile path, no writes next to the exe)
        private static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SysPulse", "error.log");

        private static void WriteLog(string text)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath));
                FileInfo fi = new FileInfo(LogPath);
                if (fi.Exists && fi.Length > 1024 * 1024) fi.Delete(); // cap size at 1 MB
                File.AppendAllText(LogPath, DateTime.Now.ToString("s") + " " + text + Environment.NewLine);
            }
            catch { }
        }

        [STAThread]
        static void Main(string[] args)
        {
            // SECURITY: restrict native DLL loading for the whole process to System32 (DLL planting)
            try { NativeMethods.SetDefaultDllDirectories(NativeMethods.LOAD_LIBRARY_SEARCH_SYSTEM32); } catch { }

            // Single instance: two copies would fight over power plans / restore state
            bool createdNew;
            using (Mutex mtx = new Mutex(true, @"Local\SysPulse_SingleInstance", out createdNew))
            {
                if (!createdNew) return;

                Application.ThreadException += (s, e) => WriteLog(e.Exception.ToString());
                AppDomain.CurrentDomain.UnhandledException += (s, e) => WriteLog(e.ExceptionObject.ToString());
                try
                {
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new MainForm());
                }
                catch (Exception ex)
                {
                    WriteLog(ex.ToString());
                }
            }
        }
    }
}
