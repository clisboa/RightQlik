using System;
using System.Net;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;
using System.Security.Principal;
using System.Diagnostics;
using System.Reflection;
using System.ComponentModel;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;

namespace RightQlik
{
    class Program
    {

        [Flags]
        public enum RegOption
        {
            NonVolatile = 0x0,
            Volatile = 0x1,
            CreateLink = 0x2,
            BackupRestore = 0x4,
            OpenLink = 0x8
        }

        [Flags]
        public enum RegSAM
        {
            QueryValue = 0x0001,
            SetValue = 0x0002,
            CreateSubKey = 0x0004,
            EnumerateSubKeys = 0x0008,
            Notify = 0x0010,
            CreateLink = 0x0020,
            WOW64_32Key = 0x0200,
            WOW64_64Key = 0x0100,
            WOW64_Res = 0x0300,
            Read = 0x00020019,
            Write = 0x00020006,
            Execute = 0x00020019,
            AllAccess = 0x000f003f,
            AllAccess_64 = 0x000f013f
        }

        [Flags]
        public enum DWType
        {
            REG_NONE = 0,
            REG_SZ = 1,
            REG_EXPAND_SZ = 2,
            REG_BINARY = 3, 
            REG_DWORD = 4,
            REG_DWORD_LITTLE_ENDIAN = 4,
            REG_DWORD_BIG_ENDIAN = 5, 
            REG_LINK = 6,
            REG_MULTI_SZ = 7,
            REG_RESOURCE_LIST = 8,
            REG_FULL_RESOURCE_DESCRIPTOR = 9,
            REG_RESOURCE_REQUIREMENTS_LIST = 10,
            REG_QWORD = 11,
            REG_QWORD_LITTLE_ENDIAN = 11
        }

        public enum RegResult
        {
            CreatedNewKey = 0x00000001,
            OpenedExistingKey = 0x00000002
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("advapi32.dll")]
        static extern int RegOpenKeyEx(
              RegistryHive hKey,
              [MarshalAs(UnmanagedType.VBByRefStr)] ref string subKey,
              RegOption dwOptions,
              RegSAM samDesired,
              out UIntPtr phkResult);

        [DllImport("advapi32.dll")]
        static extern int RegDeleteValue(
              UIntPtr hKey,
              [MarshalAs(UnmanagedType.VBByRefStr)] ref string lpValueName
              );

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int RegCreateKeyEx(
                    RegistryHive hKey,
                    string lpSubKey,
                    int Reserved,
                    string lpClass,
                    RegOption dwOptions,
                    RegSAM samDesired,
                    //UIntPtr lpSecurityAttributes,
                    SECURITY_ATTRIBUTES lpSecurityAttributes,
                    out UIntPtr phkResult,
                    out RegResult lpdwDisposition);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int RegSetValueEx(
                    UIntPtr hKey,
                    [MarshalAs(UnmanagedType.LPStr)] string lpValueName,
                    int Reserved,
                    RegistryValueKind dwtype,
                    //IntPtr lpData,
                    StringBuilder lpData,
                    int cbData);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern int RegCloseKey(
            UIntPtr hKey);


        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(
            [In] IntPtr hProcess,
            [Out] out bool wow64Process
        );

        static void Main(string[] args)
        {
 
            WindowsPrincipal pricipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool hasAdministrativeRight = pricipal.IsInRole(WindowsBuiltInRole.Administrator);
            if (!hasAdministrativeRight)
            {
                // relaunch the application with admin rights
                string fileName = Assembly.GetExecutingAssembly().Location;
                ProcessStartInfo processInfo = new ProcessStartInfo();
                processInfo.Verb = "runas";
                processInfo.FileName = fileName;

                try
                {
                    Process.Start(processInfo);
                }
                catch (Win32Exception)
                {
                    MessageBox.Show("In order to install RightQlik, you need to launch the installer with administrative rights. Please try again.");
                }

                return;
            }

            UIntPtr hKey;
            RegResult regResult;

            String qvPath = GetEXELocation();

            if (string.IsNullOrEmpty(qvPath))
            {
                return;
            }
            RegSAM accessType;
            if (InternalCheckIsWow64())
            {
                //Console.WriteLine("64-bit system detected");
                accessType = RegSAM.AllAccess_64;
            }
            else
            {
                //Console.WriteLine("32-bit system detected");
                accessType = RegSAM.AllAccess;
            }

            const string progId = "QlikView.Document";
            const string subkey = "shell";
            string subkeyName = progId + "\\" + subkey + "\\" +"RightQlik";

            SECURITY_ATTRIBUTES secAttribs = new SECURITY_ATTRIBUTES();
            int result = RegCreateKeyEx(RegistryHive.ClassesRoot, subkeyName, 0, String.Empty, RegOption.NonVolatile, RegSAM.AllAccess_64, secAttribs, out hKey, out regResult);

            //MessageBox.Show("Starting...");

            string subKeyValueName_MUI = "MUIVerb";
            string subkeyData_MUI = "RightQlik";
            StringBuilder regData_MUI = new StringBuilder(subkeyData_MUI);
            int cbData_MUI = regData_MUI.Capacity;
            RegSetValueEx(hKey, subKeyValueName_MUI, 0, RegistryValueKind.String, regData_MUI, cbData_MUI);

            string subKeyValueName_SubCmd = "SubCommands";
            string subkeyData_SubCmd = "QV.OpenNewInstance;QV.OpenNoData;QV.Reload;QV.ReloadKeepOpen;QV.VisitUs";
            StringBuilder regData_SubCmd = new StringBuilder(subkeyData_SubCmd);
            int cbData_SubCmd = regData_SubCmd.Capacity;
            RegSetValueEx(hKey, subKeyValueName_SubCmd, 0, RegistryValueKind.String, regData_SubCmd, cbData_SubCmd);
            
            RegCloseKey(hKey);

            /**** Writing the Command Store ***/

                /***** QV.OpenNewInstance ***/
                    string subCommand1_KeyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell\\" + "QV.OpenNewInstance";

                    string subCommand1_DisplayName = "Open in a new QV instance";
                    StringBuilder regData_subCommand1_DisplayName = new StringBuilder(subCommand1_DisplayName);
                    int cbData_subCommand1_DisplayName = regData_subCommand1_DisplayName.Capacity;

                    string subCommand1_CommandKeyName = subCommand1_KeyName + "\\" + "command";
                    StringBuilder regData_subCommand1_CommandKeyName = new StringBuilder(subCommand1_CommandKeyName);

                    string subCommand1_Command = "\"" + qvPath + "\" %1";

                    StringBuilder regData_subCommand1_Command = new StringBuilder(subCommand1_Command);
                    int cbData_subCommand1_Command = regData_subCommand1_Command.Capacity;

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand1_KeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand1_DisplayName, cbData_subCommand1_DisplayName);
                    RegCloseKey(hKey);

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand1_CommandKeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand1_Command, cbData_subCommand1_Command);
                    RegCloseKey(hKey);

               /***** QV.OpenNoData ***/
                    string subCommand2_KeyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell\\" + "QV.OpenNoData";

                    string subCommand2_DisplayName = "Open without data";
                    StringBuilder regData_subCommand2_DisplayName = new StringBuilder(subCommand2_DisplayName);
                    int cbData_subCommand2_DisplayName = regData_subCommand2_DisplayName.Capacity;

                    string subCommand2_CommandKeyName = subCommand2_KeyName + "\\" + "command";
                    StringBuilder regData_subCommand2_CommandKeyName = new StringBuilder(subCommand2_CommandKeyName);

                    string subCommand2_Command = "\"" + qvPath + "\" %1 /NoData";
                    StringBuilder regData_subCommand2_Command = new StringBuilder(subCommand2_Command);
                    int cbData_subCommand2_Command = regData_subCommand2_Command.Capacity;

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand2_KeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand2_DisplayName, cbData_subCommand2_DisplayName);
                    RegCloseKey(hKey);

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand2_CommandKeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand2_Command, cbData_subCommand2_Command);
                    RegCloseKey(hKey);

               /***** QV.Reload ***/
                    string subCommand3_KeyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell\\" + "QV.Reload";

                    string subCommand3_DisplayName = "Reload document";
                    StringBuilder regData_subCommand3_DisplayName = new StringBuilder(subCommand3_DisplayName);
                    int cbData_subCommand3_DisplayName = regData_subCommand3_DisplayName.Capacity;

                    string subCommand3_CommandKeyName = subCommand3_KeyName + "\\" + "command";
                    StringBuilder regData_subCommand3_CommandKeyName = new StringBuilder(subCommand3_CommandKeyName);

                    string subCommand3_Command = "\"" + qvPath + "\" %1 /r";
                    StringBuilder regData_subCommand3_Command = new StringBuilder(subCommand3_Command);
                    int cbData_subCommand3_Command = regData_subCommand3_Command.Capacity;

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand3_KeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand3_DisplayName, cbData_subCommand3_DisplayName);
                    RegCloseKey(hKey);

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand3_CommandKeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand3_Command, cbData_subCommand3_Command);
                    RegCloseKey(hKey);


               /***** QV.ReloadKeepOpen ***/
                    string subCommand4_KeyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell\\" + "QV.ReloadKeepOpen";

                    string subCommand4_DisplayName = "Reload and keep open";
                    StringBuilder regData_subCommand4_DisplayName = new StringBuilder(subCommand4_DisplayName);
                    int cbData_subCommand4_DisplayName = regData_subCommand4_DisplayName.Capacity;

                    string subCommand4_CommandKeyName = subCommand4_KeyName + "\\" + "command";
                    StringBuilder regData_subCommand4_CommandKeyName = new StringBuilder(subCommand4_CommandKeyName);

                    string subCommand4_Command = "\"" + qvPath + "\" %1 /l";
                    StringBuilder regData_subCommand4_Command = new StringBuilder(subCommand4_Command);
                    int cbData_subCommand4_Command = regData_subCommand4_Command.Capacity;

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand4_KeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand4_DisplayName, cbData_subCommand4_DisplayName);
                    RegCloseKey(hKey);

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand4_CommandKeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand4_Command, cbData_subCommand4_Command);
                    RegCloseKey(hKey);

               /***** QV.VisitUs ***/
                    string QlikOnURL = "http://q-on.bi/go/rq"; 
                    string subCommand5_KeyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell\\" + "QV.VisitUs";

                    string subCommand5_DisplayName = "Qlik On!";
                    StringBuilder regData_subCommand5_DisplayName = new StringBuilder(subCommand5_DisplayName);
                    int cbData_subCommand5_DisplayName = regData_subCommand5_DisplayName.Capacity;

                    string subCommand5_CommandKeyName = subCommand5_KeyName + "\\" + "command";
                    StringBuilder regData_subCommand5_CommandKeyName = new StringBuilder(subCommand5_CommandKeyName);

                    string subCommand5_Command = "\"IExplore.exe\"" + " \"" + QlikOnURL + "\"";
                    StringBuilder regData_subCommand5_Command = new StringBuilder(subCommand5_Command);
                    int cbData_subCommand5_Command = regData_subCommand5_Command.Capacity;

                    string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                    string iconPath = appDataPath + "\\" + "RightQlik";
                    string iconFileName = iconPath + "\\" + "RightQlik.ico";
                    System.IO.Directory.CreateDirectory(iconPath);

                    //Console.WriteLine("Icon will be saved on: " + iconFileName);

                    string subCommand5_IconVerb = "Icon";
                    string subCommand5_IconData = iconFileName;
                    StringBuilder regData_subCommand5_IconVerb = new StringBuilder(subCommand5_IconData);
                    int cbData_subCommand5_IconVerb = regData_subCommand5_IconVerb.Capacity;

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand5_KeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand5_DisplayName, cbData_subCommand5_DisplayName);
                    RegSetValueEx(hKey, subCommand5_IconVerb, 0, RegistryValueKind.String, regData_subCommand5_IconVerb, cbData_subCommand5_IconVerb);
            
                    RegCloseKey(hKey);

                    result = RegCreateKeyEx(RegistryHive.LocalMachine, subCommand5_CommandKeyName, 0, String.Empty, RegOption.NonVolatile, accessType, secAttribs, out hKey, out regResult);
                    RegSetValueEx(hKey, String.Empty, 0, RegistryValueKind.String, regData_subCommand5_Command, cbData_subCommand5_Command);
                    RegCloseKey(hKey);
                    
                    using (Stream input = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("RightQlik.RightQlik.ico"))
                    using (Stream output = File.Create(iconFileName))
                    {
                        CopyStream(input, output);
                    }

            //MessageBox.Show("Set...");

            Console.WriteLine("\r\nRightQlik has been installed");
            Console.WriteLine("Press enter to finish");
            Console.ReadLine();
        }

        public static void CopyStream(Stream input, Stream output)
        {
            // Insert null checking here for production
            byte[] buffer = new byte[8192];

            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, bytesRead);
            }
        }

        public static void WriteTo(Stream sourceStream, Stream targetStream)
        {
            byte[] buffer = new byte[0x10000];
            int n;
            while ((n = sourceStream.Read(buffer, 0, buffer.Length)) != 0)
                targetStream.Write(buffer, 0, n);
        }

        public static String GetEXELocation()
        {
            string programFilesPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string qvFile = programFilesPath + "\\QlikView\\qv.exe";
            string qvFile_x64 = qvFile.Replace(" (x86)", "");
            if (File.Exists(qvFile_x64))
            {
                return qvFile_x64;
            }
            else if (File.Exists(qvFile))
            {
                return qvFile;
            }
            else
            {
                Console.WriteLine("We couldn't find qv.exe in the default locations. (" + qvFile + ")");
                Console.WriteLine("To continue the installation, please enter the full path to the location of qv.exe in your system:");
                string custom_qvFile = Console.ReadLine();
                if (File.Exists(custom_qvFile))
                {
                    return custom_qvFile;
                }
                else
                {
                    Console.WriteLine("The path you entered may be incorrect, please enter it again:");
                    string custom_qvFile_2 = Console.ReadLine();
                    if (File.Exists(custom_qvFile_2))
                    {
                        return custom_qvFile_2;
                    }
                    else
                    {
                        Console.WriteLine("We couldn't find the qv.exe file in your system.");
                        Console.WriteLine("Press enter to finish");
                        Console.ReadLine(); 
                        return null;
                    }
                }

            }
        }

        public static bool InternalCheckIsWow64()
        {
            if ((Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1) ||
                Environment.OSVersion.Version.Major >= 6)
            {
                using (Process p = Process.GetCurrentProcess())
                {
                    bool retVal;
                    if (!IsWow64Process(p.Handle, out retVal))
                    {
                        return false;
                    }
                    return retVal;
                }
            }
            else
            {
                return false;
            }
        }
    }
}
