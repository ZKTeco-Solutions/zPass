using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Newtonsoft.Json;

namespace zPassLibrary
{
    public class StringTools
    {
        public static string ToSnakeCase(string str)
        {
            return string.Concat(str.Select((x, i) => i > 0 && char.IsUpper(x) ? "_" + x.ToString() : x.ToString())).ToLower();
        }
        public static string ToBase58String(byte[] data)
        {
            return Base58Check.Base58CheckEncoding.EncodePlain(data);
        }

        public static byte[] FromBase58String(string s)
        {
            return Base58Check.Base58CheckEncoding.DecodePlain(s);
        }
        public static bool NoEmptyString(params string[] str)
        {
            foreach (var s in str)
            {
                if (string.IsNullOrEmpty(s))
                    return false;
            }

            return true;
        }

        public enum PasswordValidationErrors
        {
            Valid = 0,
            MinimumLength = 1,
            NoLetters = 1 << 1,
            NoDigits = 1 << 2,
            NoSpecial = 1 << 3
        }


        public static PasswordValidationErrors ValidatePassword(string pwd)
        {
            var result = PasswordValidationErrors.Valid;

            pwd = pwd.Trim();
            if (pwd.Length < 8)
            {
                result |= PasswordValidationErrors.MinimumLength;
            }

            if (pwd.Count(x => char.IsLetter(x)) == 0)
            {
                result |= PasswordValidationErrors.NoLetters;
            }

            if (pwd.Count(x => char.IsDigit(x)) == 0)
            {
                result |= PasswordValidationErrors.NoDigits;
            }

            if (pwd.Count(x => !char.IsLetterOrDigit(x)) == 0)
            {
                result |= PasswordValidationErrors.NoSpecial;
            }

            return result;

        }

        public static bool ValidateEmail(string email)
        {
            email = email.Trim();
            //there should be two consecutive dots
            if (email.IndexOf("..") != -1)
            {
                return false;
            }
            //there should be special characters
            if (email.Replace("@", "").Replace(".", "").Any(x => !(char.IsLetterOrDigit(x) || x == '_' || x == '-')))
            {
                return false;
            }

            var ndxAt = email.IndexOf("@");
            if (ndxAt < 1)
            {
                return false;
            }
            //the @ sign must be present only once
            if (email.Where(x => x == '@').Count() != 1)
            {
                return false;
            }

            var elems = email.Split(new char[] { '@' }, StringSplitOptions.RemoveEmptyEntries);
            if (elems.Length != 2)
            {
                return false;
            }
            //make sure a dot in the domain is present
            if (elems[1].Where(x => x == '.').Count() == 0)
            {
                return false;
            }
            //if dot in domain is not existing or its the first character
            if (elems[1].Length == 0 || elems[1][0] == '.')
            {
                return false;
            }


            return true;
        }

    }
}
