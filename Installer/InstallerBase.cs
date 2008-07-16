using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Reflection;

using Microsoft.Win32;

namespace WeavverLib.Installer
{
     public class InstallerBase
     {
          private string installdirectory  = "";
          private bool   installnatively   = true;
          private string userdatadirectory = "";
          private string installpath       = "";
//-------------------------------------------------------------------------------------------
          public string InstallPath
          {
               get { return installpath; }
               set { installpath = value; }
          }
//-------------------------------------------------------------------------------------------
          public string InstallDirectory
          {
               get { return installdirectory; }
               set { installdirectory = value; }
          }
//-------------------------------------------------------------------------------------------
          public string UserDataDirectory
          {
               get { return userdatadirectory; }
               set { userdatadirectory = value; }
          }
//-------------------------------------------------------------------------------------------
          public bool InstallNatively
          {
               get { return installnatively; }
               set { installnatively = value; }
          }
//-------------------------------------------------------------------------------------------
          public static bool Is32BitOS
          {
               get
               {
                    return (IntPtr.Size == 4);
               }
          }
//-------------------------------------------------------------------------------------------
          public InstallerBase(string productname)
          {
               InstallDirectory     = System.Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\" + productname;
               UserDataDirectory    = System.Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\" + productname;
               Assembly Application = Assembly.GetCallingAssembly();
               InstallPath          = Application.Location;
          }
//-------------------------------------------------------------------------------------------
          public void AddProgramsUninstallShortcut(string productname, string displayname, string version, string publisher, string abouturl, string iconpath, string uninstallpath, bool canmodify, bool canrepair)
          {
               RegistryKey uninstallKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\", true);
               RegistryKey productKey = uninstallKey.CreateSubKey(productname);
               productKey.SetValue("DisplayName", displayname);
               productKey.SetValue("DisplayVersion", version);
               productKey.SetValue("Publisher", publisher);
               productKey.SetValue("URLInfoAbout", abouturl);
               productKey.SetValue("UninstallString", uninstallpath);
               productKey.SetValue("NoModify", canmodify ? "1" : "0");
               productKey.SetValue("NoRepair", canrepair ? "1" : "0");

               productKey.Close();
               uninstallKey.Close();
          }
//-------------------------------------------------------------------------------------------
          public void DirectoryDeleteSafe(string path)
          {
               if (Directory.Exists(path))
               {
                    if (Directory.GetFiles(path).Length > 0)
                    {
                         CreateRunOnceKey("delete " + path);
                    }
                    else
                    {
                         Directory.Delete(path);
                    }
               }
          }
//-------------------------------------------------------------------------------------------
          public void FileCopySafe(string source, string destination)
          {
               if (File.Exists(destination))
               {
                    File.Move(destination, "temppatH");
               }
               File.Copy(source, destination);
          }
//-------------------------------------------------------------------------------------------
          public void FileDeleteSafe(string path)
          {
               try
               {
                    File.Delete(path);
               }
               catch
               {
                    CreateRunOnceKey("delete " + path);
               }
          }
//-------------------------------------------------------------------------------------------
          public void RemoveProgramsUninstallShortcut(string productname)
          {
               Registry.LocalMachine.DeleteSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + productname, false);
          }
//-------------------------------------------------------------------------------------------
          public void CreateRunOnceKey(string command)
          {
          }
//-------------------------------------------------------------------------------------------
          public virtual void Install()
          {
          }
//-------------------------------------------------------------------------------------------
          public virtual void Uninstall()
          {
          }
//-------------------------------------------------------------------------------------------
     }
}
