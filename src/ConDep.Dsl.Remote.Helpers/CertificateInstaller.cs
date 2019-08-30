using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ConDep.Dsl.Remote.Helpers
{
    public static class CertificateInstaller
    {
        public static void InstallCert(string filePath)
        {
            filePath = Environment.ExpandEnvironmentVariables(filePath);
            Console.WriteLine(string.Format("Installing certificate using file: [{0}].", filePath));
            var certificate = new X509Certificate2(filePath);
            AddCertToStore(certificate);
            RemoveCertFileFromDisk(filePath);
        }

        public static X509Certificate2 GetCertFromBase64(string base64Cert)
        {
            var cert = Convert.FromBase64String(base64Cert);
            return new X509Certificate2(cert);
        }

        public static void InstallCertFromBase64(string base64Cert)
        {
            var certificate = GetCertFromBase64(base64Cert);
            AddCertToStore(certificate);
        }

        public static void InstallCertToTrustedRoot(string filePath)
        {
            filePath = Environment.ExpandEnvironmentVariables(filePath);
            Console.Write("Installing certificate using file: [{0}].", filePath);
            var certificate = new X509Certificate2(filePath);
            var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            AddCertToStore(certificate, store);
            RemoveCertFileFromDisk(filePath);
        }


        public static void InstallPfx(string filePath, string password, string[] privateKeyUsers)
        {
            filePath = Environment.ExpandEnvironmentVariables(filePath);
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException(string.Format("File [{0}] not found.", filePath));
            }
            Console.WriteLine("Installing certificate using file: [{0}].", filePath);

            var cert = new X509Certificate2();
            cert.Import(filePath, password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet );

            AddCertToStore(cert);

            if (cert.HasPrivateKey)
            {
                GrantUserReadAccessToCertificate(privateKeyUsers, cert);
            }

            RemoveCertFileFromDisk(filePath);
        }

        private static void RemoveCertFromStoreIfExist(X509Certificate2 cert)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                var certs = store.Certificates;
                var result = certs.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);

                if (result.Count > 1)
                {
                    throw new Exception("More than one certificate was found.");
                }
                else if (result.Count == 1)
                {
                    Console.WriteLine("Certificate was allready in store. Deleting from store now.");
                    var storeCert = result[0];
                    store.Remove(storeCert);
                }
            }
            finally
            {
                store.Close();
            }
        }

        private static void GrantUserReadAccessToCertificate(IEnumerable<string> privateKeyUsers, X509Certificate2 certificate)
        {
            if (privateKeyUsers == null)
                return;

            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                store.Open(OpenFlags.ReadWrite);

                var certs = store.Certificates;
                var result = certs.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, false);

                if (result.Count == 1)
                {
                    var storeCert = result[0];

                    bool cng = false;
                    FileSecurity acl;
                    SafeNCryptKeyHandle handle;
                    try
                    {
                        handle = GetCspPrivateKeyFromCertificate(storeCert);
                        acl = GetCspACL(handle);
                    }
                    catch (Win32Exception e)
                    {
                        try
                        {
                            handle = GetCngPrivateKeyFromCertificate(storeCert);
                            acl = GetACL(handle);
                            cng = true;
                        }
                        catch (Win32Exception e2)
                        {
                            throw new AggregateException(e, e2);
                        }
                    }

                    foreach (var user in privateKeyUsers)
                    {
                        acl.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.Read, AccessControlType.Allow));
                    }

                    if (cng)
                    {
                        SetACL(handle, acl);
                    }
                    else
                    {
                        SetCspACL(handle, acl);
                    }

                    return;
                }

                //store.Add(certificate);
                Console.WriteLine("Certificate installed in store.");
            }
            finally
            {
                store.Close();
            }
        }

        private static void AddCertToStore(X509Certificate2 certificate)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            AddCertToStore(certificate, store);
        }

        private static void AddCertToStore(X509Certificate2 certificate, X509Store store)
        {
            try
            {
                store.Open(OpenFlags.ReadWrite);

                var certs = store.Certificates;
                var result = certs.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, false);

                //Will only add cert to store if it doesn't already exist.
                if (result.Count > 0)
                {
                    store.Close();
                    return;
                }

                store.Add(certificate);
                Console.WriteLine("Certificate installed in store.");
            }
            finally
            {
                store.Close();
            }
        }

        private static void RemoveCertFileFromDisk(string filePath)
        {
            File.Delete(filePath);
            Console.WriteLine("Certificate removed from disk.");
        }
        
        public enum ErrorCode
        {
            Success = 0, // ERROR_SUCCESS 
        }

        [Flags]
        [CLSCompliantAttribute(false)]
        public enum SECURITY_INFORMATION : uint
        {
            DACL_SECURITY_INFORMATION = 0x00000004,
        }
        [CLSCompliantAttribute(false)]
        public enum ProvParam : uint
        {
            PP_KEYSET_SEC_DESCR = 8,
        }
        [CLSCompliantAttribute(false)]
        public enum KeySpec : uint
        {
            NONE = 0x0,
            AT_KEYEXCHANGE = 0x1,
            AT_SIGNATURE = 2,
            CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
        }

        [Flags]
        private enum CryptAcquireKeyFlagControl : uint
        {
            CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000,
            CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000,
        }

        [Flags]
        [CLSCompliantAttribute(false)]
        public enum CryptAcquireKeyFlags : uint
        {
            CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001,
            CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 0x00000002,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004,
            CRYPT_ACQUIRE_NO_HEALING = 0x00000008,
            CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040,
        }

        [Flags]
        [CLSCompliantAttribute(false)]
        public enum CryptAcquireNCryptKeyFlags : uint
        {
            CRYPT_ACQUIRE_CACHE_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_CACHE_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_USE_PROV_INFO_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_NO_HEALING = CryptAcquireKeyFlags.CRYPT_ACQUIRE_NO_HEALING | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_SILENT_FLAG = CryptAcquireKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG | CryptAcquireKeyFlagControl.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [CLSCompliantAttribute(false)]
        public static extern bool CryptAcquireCertificatePrivateKey(
            IntPtr pCert,
            CryptAcquireKeyFlags dwFlags,
            IntPtr pvParameters,
            out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
            out KeySpec pdwKeySpec,
            out bool pfCallerFreeProvOrNCryptKey);


        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [CLSCompliantAttribute(false)]
        public static extern bool CryptAcquireCertificatePrivateKey(
            IntPtr pCert,
            CryptAcquireNCryptKeyFlags dwFlags,
            IntPtr pvParameters,
            out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
            out KeySpec pdwKeySpec,
            out bool pfCallerFreeProvOrNCryptKey);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [CLSCompliantAttribute(false)]
        public static extern ErrorCode NCryptGetProperty(
            SafeHandle hObject,
            [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
            SafeSecurityDescriptorPtr pbOutput,
            uint cbOutput,
            ref uint pcbResult,
            SECURITY_INFORMATION dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [CLSCompliantAttribute(false)]
        public static extern ErrorCode NCryptSetProperty(
            SafeHandle hObject,
            [MarshalAs(UnmanagedType.LPWStr)] string pszProperty,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
            uint cbInput,
            SECURITY_INFORMATION dwFlags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent,
            ref IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [CLSCompliantAttribute(false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptGetProvParam(
            SafeHandle hProv,
            ProvParam dwParam,
            SafeSecurityDescriptorPtr pbData,
            ref uint pdwDataLen,
            SECURITY_INFORMATION dwFlags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [CLSCompliantAttribute(false)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptSetProvParam(
            SafeHandle hProv,
            ProvParam dwParam,
            [MarshalAs(UnmanagedType.LPArray)] byte[] pbData,
            SECURITY_INFORMATION dwFlags);

        public class SafeSecurityDescriptorPtr : SafeHandleZeroOrMinusOneIsInvalid
        {
            private static SafeSecurityDescriptorPtr nullHandle = new SafeSecurityDescriptorPtr();

            private int size = -1;

            public SafeSecurityDescriptorPtr()
                : base(true)
            {
            }

            [CLSCompliantAttribute(false)]
            public SafeSecurityDescriptorPtr(uint size)
                : base(true)
            {
                this.size = (int)size;
                this.SetHandle(Marshal.AllocHGlobal(this.size));
            }

            public byte[] GetHandleCopy()
            {
                if (size < 0)
                {
                    throw new NotSupportedException();
                }

                byte[] buffer = new byte[size];
                Marshal.Copy(this.handle, buffer, 0, buffer.Length);

                return buffer;
            }

            protected override bool ReleaseHandle()
            {
                try
                {
                    Marshal.FreeHGlobal(this.handle);
                }
                catch
                {
                    return false;
                }
                return true;
            }
        }
        static FileSecurity GetCspACL(SafeNCryptKeyHandle handle)
        {
            uint securityDescriptorSize = 0;
            if (!CryptGetProvParam(
                    handle,
                    ProvParam.PP_KEYSET_SEC_DESCR,
                    new SafeSecurityDescriptorPtr(),
                    ref securityDescriptorSize,
                    SECURITY_INFORMATION.DACL_SECURITY_INFORMATION))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            SafeSecurityDescriptorPtr securityDescriptorBuffer = new SafeSecurityDescriptorPtr(securityDescriptorSize);

            if (!CryptGetProvParam(
                    handle,
                    ProvParam.PP_KEYSET_SEC_DESCR,
                    securityDescriptorBuffer,
                    ref securityDescriptorSize,
                    SECURITY_INFORMATION.DACL_SECURITY_INFORMATION))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            using (securityDescriptorBuffer)
            {
                FileSecurity acl = new FileSecurity();
                acl.SetSecurityDescriptorBinaryForm(securityDescriptorBuffer.GetHandleCopy());
                return acl;
            }
        }

        static void SetCspACL(SafeNCryptKeyHandle handle, FileSecurity acl)
        {
            if (!CryptSetProvParam(
                handle,
                ProvParam.PP_KEYSET_SEC_DESCR,
                acl.GetSecurityDescriptorBinaryForm(),
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        static FileSecurity GetACL(SafeNCryptKeyHandle handle)
        {
            uint securityDescriptorSize = 0;
            var code = NCryptGetProperty(
                handle,
                "Security Descr",
                new SafeSecurityDescriptorPtr(),
                0,
                ref securityDescriptorSize,
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION);
            if (code != ErrorCode.Success)
            {
                throw new Win32Exception((int)code);
            }


            SafeSecurityDescriptorPtr securityDescriptorBuffer = new SafeSecurityDescriptorPtr(securityDescriptorSize);

            code = NCryptGetProperty(
                handle,
                "Security Descr",
                securityDescriptorBuffer,
                securityDescriptorSize,
                ref securityDescriptorSize,
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION);
            if (code != ErrorCode.Success)
            {
                throw new Win32Exception((int)code);
            }

            using (securityDescriptorBuffer)
            {
                FileSecurity acl = new FileSecurity();
                acl.SetSecurityDescriptorBinaryForm(securityDescriptorBuffer.GetHandleCopy());
                return acl;
            }
        }

        private static void SetACL(SafeNCryptKeyHandle handle, FileSecurity acl)
        {
            byte[] sd = acl.GetSecurityDescriptorBinaryForm();
            var code = NCryptSetProperty(
                handle,
                "Security Descr",
                sd,
                (uint)sd.Length,
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION);
            if (code != ErrorCode.Success)
            {
                throw new Win32Exception((int)code);
            }
        }

        private static SafeNCryptKeyHandle GetCngPrivateKeyFromCertificate(X509Certificate2 certificate)
        {
            SafeNCryptKeyHandle ncryptKeyHandle;
            if (!CryptAcquireCertificatePrivateKey(
                    certificate.Handle,
                    CryptAcquireNCryptKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG | CryptAcquireNCryptKeyFlags.CRYPT_ACQUIRE_CACHE_FLAG,
                    IntPtr.Zero,
                    out ncryptKeyHandle,
                    out KeySpec keySpec,
                    out bool ownHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return ncryptKeyHandle;
        }

        private static SafeNCryptKeyHandle GetCspPrivateKeyFromCertificate(X509Certificate2 certificate)
        {
            SafeNCryptKeyHandle cspHandle;
            if (!CryptAcquireCertificatePrivateKey(
                certificate.Handle,
                CryptAcquireKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG | CryptAcquireKeyFlags.CRYPT_ACQUIRE_CACHE_FLAG,
                IntPtr.Zero,
                out cspHandle,
                out KeySpec keySpec,
                out bool ownHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return cspHandle;
        }
    }
}
