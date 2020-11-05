using System;
using System.Security.Cryptography;
using System.Text;

namespace WebApi.Helpers
{
    public class Hash
    {
        public static string GenSHA512(string s, bool l = false)
        {
            string r = "";
            try
            {
                byte[] d = Encoding.UTF8.GetBytes(s);
                using (SHA512 a = new SHA512Managed())
                {
                    byte[] h = a.ComputeHash(d);
                    r = BitConverter.ToString(h).Replace("-", "");
                }
                r = (l ? r.ToLowerInvariant() : r);
            }
            catch
            {

            }
            return r;
        }
    }
}
