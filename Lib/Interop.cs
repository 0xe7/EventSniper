using System;
using System.Collections;
using System.Collections.Generic;

namespace EventSniper
{
    public class Interop
    {
        [Flags]
        public enum KdcOptions : uint
        {
            VALIDATE = 0x00000001,
            RENEW = 0x00000002,
            UNUSED29 = 0x00000004,
            ENC_TKT_IN_SKEY = 0x00000008,
            RENEWABLEOK = 0x00000010,
            DISABLETRANSITEDCHECK = 0x00000020,
            UNUSED16 = 0x0000FFC0,
            CONSTRAINED_DELEGATION = 0x00020000,
            CANONICALIZE = 0x00010000,
            CNAMEINADDLTKT = 0x00004000,
            OK_AS_DELEGATE = 0x00040000,
            REQUEST_ANONYMOUS = 0x00008000,
            UNUSED12 = 0x00080000,
            OPTHARDWAREAUTH = 0x00100000,
            PREAUTHENT = 0x00200000,
            INITIAL = 0x00400000,
            RENEWABLE = 0x00800000,
            UNUSED7 = 0x01000000,
            POSTDATED = 0x02000000,
            ALLOWPOSTDATE = 0x04000000,
            PROXY = 0x08000000,
            PROXIABLE = 0x10000000,
            FORWARDED = 0x20000000,
            FORWARDABLE = 0x40000000,
            RESERVED = 0x80000000
        }

        public enum EncryptionType : int
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65,
            old_exp = -135
        }

        public enum PreAuthType : uint
        {
            NONE = 0,
            TGS_REQ = 1,
            AP_REQ = 1,
            ENC_TIMESTAMP = 2,
            PW_SALT = 3,
            ENC_UNIX_TIME = 5,
            SANDIA_SECUREID = 6,
            SESAME = 7,
            OSF_DCE = 8,
            CYBERSAFE_SECUREID = 9,
            AFS3_SALT = 10,
            ETYPE_INFO = 11,
            SAM_CHALLENGE = 12,
            SAM_RESPONSE = 13,
            PK_AS_REQ_19 = 14,
            PK_AS_REP_19 = 15,
            PK_AS_REQ_WIN = 15,
            PK_AS_REQ = 16,
            PK_AS_REP = 17,
            PA_PK_OCSP_RESPONSE = 18,
            ETYPE_INFO2 = 19,
            USE_SPECIFIED_KVNO = 20,
            SVR_REFERRAL_INFO = 20,
            SAM_REDIRECT = 21,
            GET_FROM_TYPED_DATA = 22,
            SAM_ETYPE_INFO = 23,
            SERVER_REFERRAL = 25,
            TD_KRB_PRINCIPAL = 102,
            PK_TD_TRUSTED_CERTIFIERS = 104,
            PK_TD_CERTIFICATE_INDEX = 105,
            TD_APP_DEFINED_ERROR = 106,
            TD_REQ_NONCE = 107,
            TD_REQ_SEQ = 108,
            PA_PAC_REQUEST = 128,
            S4U2SELF = 129,
            PA_S4U_X509_USER = 130,
            PA_PAC_OPTIONS = 167,
            PK_AS_09_BINDING = 132,
            CLIENT_CANONICALIZED = 133
        }

        public enum LogonType : uint
        {
            Unknown = 0,
            Interactive = 2,
            Network = 3,
            Batch = 4,
            Service = 5,
            Unlock = 7,
            NetworkCleartext = 8,
            NewCredentials = 9,
            RemoteInteractive = 10,
            CachedInteractive = 11
        }

        public enum Protocol : uint
        {
            ICMP = 1,
            GGP = 3,
            TCP = 6,
            EGP = 8,
            PUP = 12,
            UDP = 17,
            HMP = 20,
            RDP = 27,
            RSVP = 46,
            PPTPoGRE = 47,
            ESP = 50,
            AH = 51,
            RVD = 66,
            IGMP = 88,
            OSFP = 89
        }
    }
}
