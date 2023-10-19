using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace file_permission_checker
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string filePath = @"C:\Temp\stuff.txt";  // Replace with your network file path
            string ldapPath = "LDAP://DC=domain,DC=com"; // Replace with your domain's distinguished name

            FileSecurity fileSecurity = File.GetAccessControl(filePath);
            AuthorizationRuleCollection arc = fileSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

            foreach (FileSystemAccessRule rule in arc)
            {
                Console.WriteLine($"Identity: {rule.IdentityReference.Value}");
                Console.WriteLine($"Permissions: {rule.FileSystemRights}");
                Console.WriteLine($"Type: {rule.AccessControlType}");
                Console.WriteLine("--------------------------");

                ResolveIdentity(ldapPath, rule.IdentityReference.Value);
            }
        }

        static void ResolveIdentity(string ldapPath, string groupName)
        {
            

            using (DirectoryEntry de = new DirectoryEntry(ldapPath))
            {
                using (DirectorySearcher searcher = new DirectorySearcher(de))
                {
                    searcher.Filter = $"(&(objectCategory=group)(name={groupName}))";
                    SearchResult result = searcher.FindOne();

                    if (result != null)
                    {
                        DirectoryEntry group = result.GetDirectoryEntry();
                        foreach (object member in group.Properties["member"])
                        {
                            using (DirectoryEntry memberEntry = new DirectoryEntry($"LDAP://{member}"))
                            {
                                Console.WriteLine(memberEntry.Properties["sAMAccountName"].Value);
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Group '{groupName}' not found.");
                    }
                }
            }
        }
    }
}
