﻿using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NotSoSecure.AspDotNetWrapper
{
    class DataWriter
    {
        public static void WriteKeysToFile(string strValidationKey, string strDecryptionKey, string strValidationAlgorithm, string strDecryptionAlgorithm, byte [] byteEncryptionIV)
        {
            if (File.Exists(AspDotNetWrapper.strDecryptedTxtFilePath))
                File.Delete(AspDotNetWrapper.strDecryptedTxtFilePath);

            using (FileStream streamWriter = new FileStream(AspDotNetWrapper.strDecryptedTxtFilePath, FileMode.OpenOrCreate, FileAccess.Write))
            {
                byte[] byteData = Encoding.ASCII.GetBytes(ContantValue.strDecryptionKey + strDecryptionKey);
                streamWriter.Write(byteData, 0, byteData.Length);
                streamWriter.WriteByte((byte)'\n');

                byteData = Encoding.ASCII.GetBytes(ContantValue.strDecryptionAlgo + strDecryptionAlgorithm);
                streamWriter.Write(byteData, 0, byteData.Length);
                streamWriter.WriteByte((byte)'\n');

                byteData = Encoding.ASCII.GetBytes(ContantValue.strValidationKey + strValidationKey);
                streamWriter.Write(byteData, 0, byteData.Length);
                streamWriter.WriteByte((byte)'\n');

                byteData = Encoding.ASCII.GetBytes(ContantValue.strValidationAlgo + strValidationAlgorithm);
                streamWriter.Write(byteData, 0, byteData.Length);
                streamWriter.WriteByte((byte)'\n');

                if (byteEncryptionIV != null)
                {
                    byteData = Encoding.ASCII.GetBytes(ContantValue.strEncryptionIV + Convert.ToBase64String(byteEncryptionIV));
                    streamWriter.Write(byteData, 0, byteData.Length);
                    streamWriter.WriteByte((byte)'\n');
                }

                streamWriter.Close();
            }
        }

        public static void WritePurposeToFile(string strPurpose)
        {
            using (FileStream streamWriter = new FileStream(AspDotNetWrapper.strDecryptedTxtFilePath, FileMode.Append, FileAccess.Write))
            {
                byte[] byteData = Encoding.ASCII.GetBytes(ContantValue.strPurpose+strPurpose);
                streamWriter.Write(byteData, 0, byteData.Length);
                streamWriter.WriteByte((byte)'\n');
                streamWriter.Close();
            }
        }

        public static void WriteOtherDataToFile(EnumPurpose enumPurpose, byte[] byteClearData)
        {
            byte[] byteData = null;
            using (FileStream streamWriter = new FileStream(AspDotNetWrapper.strDecryptedTxtFilePath, FileMode.Append, FileAccess.Write))
            {
                switch (enumPurpose)
                {
                    case EnumPurpose.OWINCOOKIE:
                        byteClearData = Decompress(byteClearData);
                        byteData = Encoding.ASCII.GetBytes(ContantValue.strAspNetApplicationCookie);
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.Write(byteClearData, 0, byteClearData.Length);
                        break;
                    case EnumPurpose.OWINOAUTH:
                        byteClearData = Decompress(byteClearData);
                        byteData = Encoding.ASCII.GetBytes(ContantValue.strAspNetOAuth);
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.Write(byteClearData, 0, byteClearData.Length);
                        break;
                    case EnumPurpose.ASPXAUTH:
                        FormsAuthenticationCookie objCookie = FormAuthenticationHelper.ConvertToAuthenticationTicket(byteClearData);
                        byteData = Encoding.ASCII.GetBytes(ContantValue.strCookiePath + objCookie.CookiePath);
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.WriteByte((byte)'\n');

                        byteData = Encoding.ASCII.GetBytes(ContantValue.strExpireUTC + objCookie.ExpiresUtc.ToString());
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.WriteByte((byte)'\n');

                        byteData = Encoding.ASCII.GetBytes(ContantValue.strIsPersistent + objCookie.IsPersistent.ToString());
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.WriteByte((byte)'\n');

                        byteData = Encoding.ASCII.GetBytes(ContantValue.strIssuedUTC + objCookie.IssuedUtc.ToString());
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.WriteByte((byte)'\n');

                        byteData = Encoding.ASCII.GetBytes(ContantValue.strUserData + objCookie.UserData);
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.WriteByte((byte)'\n');

                        byteData = Encoding.ASCII.GetBytes(ContantValue.strUserName + objCookie.UserName);
                        streamWriter.Write(byteData, 0, byteData.Length);
                        break;
                    case EnumPurpose.WEBRESOURCE:
                        byteData = Encoding.ASCII.GetBytes(ContantValue.strWebResourceData);
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.Write(byteClearData, 0, byteClearData.Length);
                        break;
                    case EnumPurpose.SCRIPTRESOURCE:
                        byteData = Encoding.ASCII.GetBytes(ContantValue.strScriptResourceData);
                        streamWriter.Write(byteData, 0, byteData.Length);
                        streamWriter.Write(byteClearData, 0, byteClearData.Length);
                        break;
                    case EnumPurpose.VIEWSTATE:

                        break;
                    case EnumPurpose.UNKNOWN:

                        break;
                    default:

                        break;
                }
                streamWriter.Close();
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\nDecrypted Data");
            Console.WriteLine("--------------");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(Encoding.ASCII.GetString(byteClearData));
            Console.ResetColor();
            if (DefinePurpose.enumPurpose == EnumPurpose.VIEWSTATE)
            {
                Console.WriteLine("\n\nGenerate serealiza payload using ysoserail.net using founded keys!!");
            }
            else
            {
                Console.WriteLine("\n\nData stored at {0} file!!", AspDotNetWrapper.strDecryptedTxtFilePath);
            }
        }

        public static byte[] Compress(byte[] byteDataToCompress)
        {
            MemoryStream memoryStream = new MemoryStream();
            GZipStream gzipStream = new GZipStream(memoryStream, CompressionMode.Compress);
            MemoryStream ms = new MemoryStream(byteDataToCompress);
            ms.CopyTo(gzipStream);
            gzipStream.Close();
            return memoryStream.ToArray();
        }

        public static byte[] Decompress(byte[] byteDataToDecompress)
        {
            MemoryStream memoryStream = new MemoryStream();
            MemoryStream from = new MemoryStream(byteDataToDecompress);
            GZipStream gzipStream = new GZipStream(from, CompressionMode.Decompress);
            gzipStream.CopyTo(memoryStream);
            from.Close();
            return memoryStream.ToArray();
        }
    }
}
