using System;
using System.Collections.Generic;
using System.Text;
using Coversant.SoapBox.Server.ServerCore.Security;

namespace WeavverLib.SoapBox
{
     public sealed class DatabaseUserManagerConfig : UserManagerConfig
     {
         private const string ASSEMBLY_NAME = "Weavver.DrupalUserManager.dll";
         private string dbtype = "mysql";
         private string dbhost = "";
         private string dbuser = "";
         private string dbpass = "";
//--------------------------------------------------------------------------------------------
         public DatabaseUserManagerConfig() : base(ASSEMBLY_NAME, typeof(DatabaseUserManagerConfig).FullName)
         {
             this.SupportedSASLMechanisms.Add("PLAIN");
             //this.SupportedSASLMechanisms.Add("DIGEST-MD5");
             this.SupportsNonSASLDigestAuth = false;
             this.SupportsNonSASLPlainAuth = false;
         }
//--------------------------------------------------------------------------------------------
          public override void GetProperties(System.Xml.XmlElement xml)
          {
               base.GetProperties(xml);
               xml.SetAttribute("dbtype", dbtype);
               xml.SetAttribute("dbhost", dbhost);
               xml.SetAttribute("dbuser", dbuser);
               xml.SetAttribute("dbpass", dbpass);
          }
//--------------------------------------------------------------------------------------------
          public override void SetProperties(System.Xml.XmlElement xml)
          {
               base.SetProperties(xml);
               dbhost = xml.GetAttribute("dbtype");
               dbhost = xml.GetAttribute("dbhost");
               dbuser = xml.GetAttribute("dbuser");
               dbpass = xml.GetAttribute("dbpass");
          }
//--------------------------------------------------------------------------------------------
         protected override UserManager CreateConcreateUserManagerInstance()
         {
             return new DatabaseUserManager(this);
         }
//--------------------------------------------------------------------------------------------
         public override bool SupportsRoleManagement
         {
             get { return false; }
         }
//--------------------------------------------------------------------------------------------
         public override bool SupportsRoleEnumeration
         {
             get { return true; }
         }
//--------------------------------------------------------------------------------------------
         public override bool SupportsUserManagement
         {
             get { return false; }
         }
//--------------------------------------------------------------------------------------------
     }
}
