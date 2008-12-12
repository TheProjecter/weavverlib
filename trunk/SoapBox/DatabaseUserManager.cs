using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Principal;
using Coversant.SoapBox.Base;
using Coversant.SoapBox.Core;
using Coversant.SoapBox.Core.IQ.Auth;
using Coversant.SoapBox.Core.SASL.DigestMD5;
using Coversant.SoapBox.Server.ServerCore.Security;
using Coversant.SoapBox.Server.ServerCore.Security.Principal;

using WeavverLib.Data;

namespace WeavverLib.SoapBox
{
    /// <summary>
    /// This user manager sample shows a very a simple user manager that authenticates users. It 
    /// may be easily extended to provide real functionality in terms of user authentication and authorization. 
    /// 
    /// There are a number of features a user manager may perform that this sample does not show. For example, a user
    /// manager may provide:
    /// 1 - A full user-search infrastructure that will be used by clients to search for users on the server. 
    /// 2 - A user editing system, for creating and deleting users
    /// 3 - A user security system, for adding and removing roles from a particular user
    /// 4 - A system security system, for adding and removing roles from the entire system. 
    /// 
    /// For a more complete user manager, take a look at the SoapBox User Manager (which Coversant will 
    /// provide upon request) which is a fully production user manager supporting all of these features.
    /// 
    /// Coversant currently has user managers written for:
    /// 1 - Custom User Manager which uses a database for user and role storage. This is the default user 
    /// manager on the SoapBox Server.
    /// 2 - An Active Directory User manager, which allows the SoapBox Server to use Active Directory for 
    /// all user and role information. 
    /// 3 - An LDAP user manager, which allows the SoapBox Server to connect with any standard LDAP server 
    /// for all user and role information. This is an advanced user manager, and configuration of this requires
    /// detailed knowledge of the LDAP schema used by the orginization.
    /// 4 - An NTLM user user manager, which allows the SoapBox Server to use the older (and now depricated) NT 
    /// Domains for user and role information.
    /// </summary>
    /// <remarks>
    /// In order to compile this sample, the SoapBox Server 2007 must be installed on the system. The references in this
    /// project will then need to be pointed to the installed SoapBox Server. These Dll's will typically be found in
    /// C:\Program Files\Coversant\SoapBox Server 2007. These easiest way to do this is to remove the two Coversant
    /// references from this project, then re-add them from the appropiate location. 
    /// 
    /// To register this User Manager with an installed server, you will need to change the configruation.xml file
    /// of the server. By default, that configuration.xml looks like:
    /// 
    /// <UserManager assemblypath="Coversant.SoapBox.Server.ServerCore.dll" configurationtypename="Coversant.SoapBox.Server.ServerCore.Security.SoapBoxUserManagerConfig">
    ///	    <auth nonsasldigest="True" nonsaslplain="True">
    ///		    <mechanism>PLAIN</mechanism>
    ///		    <mechanism>DIGEST-MD5</mechanism>
    ///		    <mechanism>ANONYMOUS</mechanism>
    ///		</auth>
    ///		<register autoregister="False" />
    ///	</UserManager>
    /// 
    /// Replace the section above in the configuration.xml file with:
    /// <UserManager assemblypath="Coversant.SoapBox.Server.SampleUserManager.dll" configurationtypename="Coversant.SoapBox.Server.SampleUserManager.BasicUserManagerConfig">
    ///     <auth nonsasldigest="True" nonsaslplain="True">
    ///         <mechanism>PLAIN</mechanism>
    ///     </auth>
    /// </UserManager>
    /// 
    /// </remarks>
    public sealed class DatabaseUserManager : Coversant.SoapBox.Server.ServerCore.Security.UserManager
    {
//--------------------------------------------------------------------------------------------
        public MySqlDatabase Drupal = new MySqlDatabase();
        /// <summary>
        /// Constructor for the Basic User Manager. This method is called internally from the SoapBox Server with the
        /// appropiate configuration section passed in. 
        /// </summary>
        /// <param name="config">
        /// A Configuration section already populated by the SoapBox Server and filled with data from the
        /// server configuration file.
        /// </param>
        public DatabaseUserManager(DatabaseUserManagerConfig config) : base("Database User Manager", config)
        {
             Drupal.ConnectionString = "" +
                  "Data Source=" + config.dbhost + ";" +
                  "Database="    + config.dbname + ";" +
                  "User ID="     + config.dbuser + ";" +
                  "Password="    + config.dbpass + ";";
        }
//--------------------------------------------------------------------------------------------
        /// <summary>
        /// Called when a user attempts to authenticate using an a 'plain-text' format. This format means
        /// the password itself was passed over the wire, and must now be authenticated. While not 
        /// particularly secure, many authentication protocols require having the actual text password,
        /// and thus a Hash+Salt value can't be used. Normally a server setup to use this protocol
        /// requires TLS, which keeps the credentials from being passed over an unencrypted link.
        /// </summary>
        /// <param name="userID">The full username to be authenticated.</param>
        /// <param name="password">The users password to check.</param>
        /// <returns>
        /// A SoapBoxPrincipal, with the authentication bit properly set. If the user is 
        /// properly authenticated then roles are returned in the SoapBox Identity nested in the principal.
        /// </returns>
        public override IPrincipal AuthUserPlain(JabberID userID, string password)
        {
            SoapBoxIdentity soapBoxID = new SoapBoxIdentity(userID);
            SoapBoxPrincipal soapBoxP = new SoapBoxPrincipal(soapBoxID);

            string[] myRoles;
            if (Drupal.CheckUser(userID.FullJabberID, password, out myRoles))
            {
                 soapBoxID.SetAuthenticated();
                 soapBoxP.AddRoles(myRoles);
            }
            return soapBoxP;
        }
//--------------------------------------------------------------------------------------------
        /// <summary>
        /// Called when a user attempts to authenticate using an a 'digest' format. This format means
        /// the a hash of the password and the SessionId was passed over the wire and must now be 
        /// authenticated. This is signifigantly more secure than a plain-text authentication, but still
        /// not considered truly 'secure'. 
        /// </summary>
        /// <param name="userID">The full username to be authenticated.</param>
        /// <param name="sessionID">
        /// The Session ID associated with this user upon stream initiation. 
        /// The password hash (digest) is built using this as a Salt value.
        /// </param>
        /// <param name="userDigest">The hash of the users password and the Session Id</param>
        /// <returns>
        /// A SoapBoxPrincipal, with the authentication bit properly set. If the user is 
        /// properly authenticated then roles are returned in the SoapBox Identity nested in the principal.
        /// </returns>
        //public override IPrincipal AuthUserNonSASLDigest(JabberID userID, string sessionID, Digest userDigest)
        //{
        //    if (userDigest == null) throw new ArgumentNullException("userDigest");

        //    SoapBoxIdentity soapBoxID = new SoapBoxIdentity(userID);
        //    SoapBoxPrincipal soapBoxP = new SoapBoxPrincipal(soapBoxID);

        //    // Normally the line below would be a database dip to lookup 
        //    // the actual password for the user who is attempting to 
        //    // authenticate. Here, I'm skipping that and mandating the 
        //    // password to be "Coversant".
        //    string textPassword = "Coversant";

        //    // Create a Digest (using the proper algorithm) of the actual password 
        //    // and the session ID
        //    Digest x = new Digest(textPassword, sessionID);

        //    // Compare the two digest values and see if they match
        //    if (string.Equals(x.DigestValue, userDigest.DigestValue,
        //                            StringComparison.OrdinalIgnoreCase))
        //    {
        //        // Normally this role lookup involves a database dip of some 
        //        // sort to determine what roles the user has. In this 
        //        // example, I'm just hardcoding them.
        //        string[] myRoles = new string[] { "Administrator", "User" };

        //        //soapBoxP.AddRoles(myRoles);
        //        //soapBoxID.SetAuthenticated();
        //    }

        //    return soapBoxP;
        //}
//--------------------------------------------------------------------------------------------
        /// <summary>
        /// Provides a mechanism for the user manager to lookup a principal for a user at any time. This is 
        /// required by the DigestMD5 SASL algorithm. If you don't need to suppor this algorithm, then this 
        /// method isn't needed.
        /// </summary>
        /// <param name="userID">The full username to build a principal for.</param>
        /// <param name="authenticated">The authenticated state for the user</param>
        /// <returns></returns>
        public override IPrincipal GetPrincipal(JabberID userID, bool authenticated)
        {
            SoapBoxIdentity soapBoxID = new SoapBoxIdentity(userID);
            SoapBoxPrincipal soapBoxP = new SoapBoxPrincipal(soapBoxID);

            if (authenticated)
            {
                // Normally this role lookup involves a database dip of 
                // some sort to determine what roles the 
                // user has. In this example, I'm just hardcoding them.
                string[] myRoles = new string[] { "Administrator", "User" };
                soapBoxP.AddRoles(myRoles);

                soapBoxID.SetAuthenticated();
            }

            return soapBoxP;
        }
//--------------------------------------------------------------------------------------------
        public override string GetDigestMD5AuthHashAsHexString(string user, string realm)
        {
            JabberID jid = new JabberID(user, realm, string.Empty);
            // Normally, we would go out to the database here and pull in the 
            // password hash that was saved when the users account was created. 
            // For this example, I'm hardcoding the password, and generating 
            // the hash on the fly.
            string password = "";
            string hash = DigestMD5AuthMechanism.CreateUserRealmSecretHashAsHexString(jid.UserName, jid.Server, password);
            return hash;
        }
//--------------------------------------------------------------------------------------------
        /// <summary>
        /// Returns a list of distribute roles supported by this user manager. The breakup of roles into security roles
        /// and distribution roles is based on the way Active Directory works. For most user managers, these two lists
        /// of roles are going to be identical.
        /// </summary>
        /// <returns>
        /// An array of strings that represent the distribution roles. 
        /// </returns>
        protected override string[] ReadAllDistributionRoles()
        {
            return Drupal.ReadAllSecurityRoles();
        }
//--------------------------------------------------------------------------------------------
        protected override string[] ReadAllSecurityRoles()
        {
             return Drupal.ReadAllSecurityRoles(); ;
        }
//--------------------------------------------------------------------------------------------
        public new DatabaseUserManagerConfig Configuration
        {
            get { return base.Configuration as DatabaseUserManagerConfig; }
        }
//--------------------------------------------------------------------------------------------
    }
}
