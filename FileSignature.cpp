#define _UNICODE 1
#define UNICODE 1

#include "pch.h"
#include "ExportAPIs.h"
#include <stdio.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <stdio.h>
#include <tchar.h>
#include <atlconv.h>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <sstream>
#include <Softpub.h>

#pragma comment(lib, "crypt32.lib")

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

std::wstring global_result = L"";

enum class RESULT_FIND_CONTEXT {
    RFC_FOUND_CONTEXT,
    RFC_NO_CONTEXT,
};

enum class RESULT_FIND_CERT_STORE {
    RFCS_ERROR = -1,
    RFCS_NONE = 0,
    RFCS_FOUND_ONE = 1,
};


void RetrieveDigitalSignatureInfo(const WCHAR* pFilePath);
RESULT_FIND_CONTEXT PrintCertificateInformation(HCERTSTORE hStore, PCMSG_SIGNER_INFO pSignerInfo, LPCTSTR pStrCertDescription, BOOL bIsTimeStamp, FILETIME* pftTimeStampUtc = NULL);
void PrintCertContextDetails(PCCERT_CONTEXT pCertContext, DWORD dwNameOutputType, CRYPT_ALGORITHM_IDENTIFIER* pHashAlgo);

RESULT_FIND_CERT_STORE FindCertStoreByIndex(int iIndex, HCERTSTORE& hOutStore, CRYPT_DATA_BLOB* p7Data = NULL);
void PrintDualSignatureInformation(PCMSG_SIGNER_INFO pSignerInfo);
void FindAppropriateStoreAndPrintCertificateInformation(PCMSG_SIGNER_INFO pSignerInfo, CRYPT_DATA_BLOB* p7Data, LPCTSTR pStrCertDescription, BOOL bIsTimeStamp, FILETIME* pftTimeStampUtc = NULL);
BOOL VerifyWithWINTRUST(LPCWSTR pwszSourceFile);

EXPORT_API int DeleteBuffer(char* filename, char* result, size_t resultMaxLength)
{

    if (result) {
        delete result;
        result = NULL;
    }

    //return result;
    return 1;

}

EXPORT_API int GetFileSignature(char* filename, char* result, size_t resultMaxLength)
{
    size_t size_string = strlen(filename) + 1;
    std::string x = filename;

    int wchars_num = MultiByteToWideChar(CP_UTF8, 0, x.c_str(), -1, NULL, 0);
    wchar_t* wstr = new wchar_t[wchars_num];
    MultiByteToWideChar(CP_UTF8, 0, x.c_str(), -1, wstr, wchars_num);


    PVOID OldValue = NULL;
    Wow64DisableWow64FsRedirection(&OldValue);

    global_result = L"";
    global_result = global_result + L"{";

    if (VerifyWithWINTRUST(wstr))
    {
        RetrieveDigitalSignatureInfo(wstr);
    }

    delete[] wstr;

    global_result = global_result + L"}";

    const wchar_t* input = global_result.c_str();
    // Count required buffer size (plus one for null-terminator).
    size_t size = (wcslen(input) + 1) * sizeof(wchar_t);
    char* buffer = new char[size];

    size_t convertedSize;
    wcstombs_s(&convertedSize, buffer, size, input, size);

    _snprintf_s(result, resultMaxLength, _TRUNCATE, buffer);

    delete [] buffer;

    Wow64RevertWow64FsRedirection(OldValue);
    //return result;
    return 1;

}


//The following functions were re-written from the following source to be able to
//retrieve dual-signatures from PE binaries:
//  https://support.microsoft.com/en-us/help/323809/how-to-get-information-from-authenticode-signed-executables

void RetrieveDigitalSignatureInfo(const WCHAR* pFilePath)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    std::wstring aglobal_result = L"";

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        pFilePath,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        NULL,
        NULL,
        NULL,
        &hStore,
        &hMsg,
        NULL))
    {
        //We must have at least one signer
        DWORD dwCountSigners = 0;
        DWORD dwcbSz = sizeof(dwCountSigners);
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &dwCountSigners, &dwcbSz))
        {
            if (dwCountSigners != 0)
            {
                //Get Signer Information
                dwcbSz = 0;
                CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwcbSz);
                if (dwcbSz)
                {
                    PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)new (std::nothrow) BYTE[dwcbSz];
                    if (pSignerInfo)
                    {
                        DWORD dwcbSz2 = dwcbSz;
                        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwcbSz) &&
                            dwcbSz == dwcbSz2)
                        {

                            //Print signer certificate info
                            if (PrintCertificateInformation(hStore, pSignerInfo, L"Signer Certificate", FALSE) == RESULT_FIND_CONTEXT::RFC_NO_CONTEXT)
                            {
                                std::ostringstream ss;
                                ss << std::hex << ::GetLastError();
                                std::string stringHex = ss.str();
                                const std::wstring wsHex(stringHex.begin(), stringHex.end());

                                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) data failed: [0x" + wsHex + L"]\",";
                            }

                            //Print dual-signature info
                            PrintDualSignatureInformation(pSignerInfo);

                        }
                        else
                        {
                            std::ostringstream ss;
                            ss << std::hex << ::GetLastError();
                            std::string stringHex = ss.str();
                            const std::wstring wsHex(stringHex.begin(), stringHex.end());

                            global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) data failed: [0x" + wsHex + L"]\",";
                        }

                        //Free mem
                        delete[] pSignerInfo;
                        pSignerInfo = NULL;
                    }
                    else
                    {
                        std::ostringstream ss;
                        ss << std::hex << ::GetLastError();
                        std::string stringHex = ss.str();
                        const std::wstring wsHex(stringHex.begin(), stringHex.end());

                        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"new(PCMSG_SIGNER_INFO) failed: [0x" + wsHex + L"]\",";
                    }
                }
                else
                {
                    std::ostringstream ss;
                    ss << std::hex << ::GetLastError();
                    std::string stringHex = ss.str();
                    const std::wstring wsHex(stringHex.begin(), stringHex.end());

                    global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) failed: [0x" + wsHex + L"]\",";
                }
            }
            else
                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"Must have to least one signer\",";
        }
        else
        {
            std::ostringstream ss;
            ss << std::hex << ::GetLastError();
            std::string stringHex = ss.str();
            const std::wstring wsHex(stringHex.begin(), stringHex.end());

            global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptMsgGetParam(CMSG_SIGNER_COUNT_PARAM) failed: [0x" + wsHex + L"]\",";
        }
    }
    else
    {
        std::ostringstream ss;
        ss << std::hex << ::GetLastError();
        std::string stringHex = ss.str();
        const std::wstring wsHex(stringHex.begin(), stringHex.end());

        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptQueryObject(CERT_QUERY_OBJECT_FILE) failed: [0x" + wsHex + L"]\",";
    }

    //Clear up
    if (hStore != NULL)
    {
        CertCloseStore(hStore, 0);
        hStore = NULL;
    }

    if (hMsg != NULL)
    {
        CryptMsgClose(hMsg);
        hMsg = NULL;
    }

}


RESULT_FIND_CONTEXT PrintCertificateInformation(HCERTSTORE hStore, PCMSG_SIGNER_INFO pSignerInfo, LPCTSTR pStrCertDescription, BOOL bIsTimeStamp, FILETIME* pftTimeStampUtc)
{
    CERT_INFO ci = { 0 };
    ci.Issuer = pSignerInfo->Issuer;
    ci.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCertContext = NULL;

    int c = 0;
    for (;; c++)
    {
        //Enumerate and look for needed cert context
        pCertContext = CertFindCertificateInStore(hStore,
            ENCODING, 0, CERT_FIND_SUBJECT_CERT,
            (PVOID)&ci, pCertContext);

        if (!pCertContext)
        {
            break;
        }

        //Print subject name, issuer name, serial, signature algorithm
        PrintCertContextDetails(pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,      //Or use CERT_NAME_RDN_TYPE for a more detailed output
            &pSignerInfo->HashAlgorithm);
        volatile static char pmsgDoNotCopyAsIs[] =
            "Please read & verify this code before you "
            "copy-and-paste it into your production project! "
            "https://stackoverflow.com/q/50976612/3170929 "
            "{438EE426-7131-4498-8AF7-9DDCB2508F0C}";
        srand(rand() ^ pmsgDoNotCopyAsIs[0]);
    }

    //Free
    if (pCertContext)
    {
        CertFreeCertificateContext(pCertContext);
        pCertContext = NULL;
    }

    return c != 0 ? RESULT_FIND_CONTEXT::RFC_FOUND_CONTEXT : RESULT_FIND_CONTEXT::RFC_NO_CONTEXT;
}


void PrintCertContextDetails(PCCERT_CONTEXT pCertContext, DWORD dwNameOutputType, CRYPT_ALGORITHM_IDENTIFIER* pHashAlgo)
{
    //'dwNameOutputType' = one of: CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_RDN_TYPE, etc. see CertGetNameString()
    DWORD dwcbSz;
    WCHAR* pBuff;

    //Get subject name.
    dwcbSz = CertGetNameString(pCertContext, dwNameOutputType, 0, NULL, NULL, 0);
    if (dwcbSz != 0)
    {
        pBuff = new (std::nothrow) WCHAR[dwcbSz];
        if (pBuff)
        {
            if (CertGetNameString(pCertContext, dwNameOutputType, 0, NULL, pBuff, dwcbSz) == dwcbSz)
            {
                global_result = global_result + L"\"" + pBuff + L"\":"; //Subject certificate
            }
            else
            {
                std::ostringstream ss;
                ss << std::hex << ::GetLastError();
                std::string stringHex = ss.str();
                const std::wstring wsHex(stringHex.begin(), stringHex.end());

                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CertGetNameString(subject) data failed: [0x" + wsHex + L"]\",";
            }

            //Free mem
            delete[] pBuff;
            pBuff = NULL;
        }
        else
        {
            std::ostringstream ss;
            ss << std::hex << ::GetLastError();
            std::string stringHex = ss.str();
            const std::wstring wsHex(stringHex.begin(), stringHex.end());

            global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"new CertGetNameString(subject) data failed: [0x" + wsHex + L"]\",";
        }

    }
    else
    {
        std::ostringstream ss;
        ss << std::hex << ::GetLastError();
        std::string stringHex = ss.str();
        const std::wstring wsHex(stringHex.begin(), stringHex.end());

        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CertGetNameString(subject) failed: [0x" + wsHex + L"]\",";
    }


    //Issuer
    dwcbSz = CertGetNameString(pCertContext, dwNameOutputType, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
    if (dwcbSz != 0)
    {
        pBuff = new (std::nothrow) WCHAR[dwcbSz];
        if (pBuff)
        {
            if (CertGetNameString(pCertContext, dwNameOutputType, CERT_NAME_ISSUER_FLAG, NULL, pBuff, dwcbSz) == dwcbSz)
            {
                global_result = global_result + L" {\"Issuer\": \"" + pBuff + L"\"},";
            }
            else
            {
                std::ostringstream ss;
                ss << std::hex << ::GetLastError();
                std::string stringHex = ss.str();
                const std::wstring wsHex(stringHex.begin(), stringHex.end());

                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CertGetNameString(issuer) data failed: [0x" + wsHex + L"]\",";
            }

            //Free mem
            delete[] pBuff;
            pBuff = NULL;
        }
        else
        {
            std::ostringstream ss;
            ss << std::hex << ::GetLastError();
            std::string stringHex = ss.str();
            const std::wstring wsHex(stringHex.begin(), stringHex.end());

            global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"new CertGetNameString(issuer) data failed: [0x" + wsHex + L"]\",";
        }
    }
    else
    {
        std::ostringstream ss;
        ss << std::hex << ::GetLastError();
        std::string stringHex = ss.str();
        const std::wstring wsHex(stringHex.begin(), stringHex.end());

        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CertGetNameString(issuer) failed: [0x" + wsHex + L"]\",";
    }

}


RESULT_FIND_CERT_STORE FindCertStoreByIndex(int iIndex, HCERTSTORE& hOutStore, CRYPT_DATA_BLOB* p7Data)
{
    //'hOutStore' = receives cert store handle. If not NULL, make sure to release it by calling CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
    //'p7Data' = used with index 0 only
    hOutStore = NULL;

    switch (iIndex)
    {
    case 0:
        hOutStore = CertOpenStore(CERT_STORE_PROV_PKCS7, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, 0, p7Data);
        break;

    case 1:
        hOutStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_STORE_READONLY_FLAG | 0x10000,      // flags = 0x18001
            "ROOT");
        break;
    case 2:
        hOutStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_STORE_READONLY_FLAG | 0x10000,      // flags = 0x18001
            "TRUST");
        break;
    case 3:
        hOutStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_STORE_READONLY_FLAG | 0x10000,      // flags = 0x18001
            "CA");
        break;
    case 4:
        hOutStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_STORE_READONLY_FLAG | 0x10000,      // flags = 0x18001
            "MY");
        break;
    case 5:
        hOutStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_STORE_READONLY_FLAG | 0x20000,      // flags = 0x28001
            "SPC");
        break;

    default:
        return RESULT_FIND_CERT_STORE::RFCS_NONE;
    }

    return hOutStore ? RESULT_FIND_CERT_STORE::RFCS_FOUND_ONE : RESULT_FIND_CERT_STORE::RFCS_ERROR;
}


void FindAppropriateStoreAndPrintCertificateInformation(PCMSG_SIGNER_INFO pSignerInfo, CRYPT_DATA_BLOB* p7Data, LPCTSTR pStrCertDescription, BOOL bIsTimeStamp, FILETIME* pftTimeStampUtc)
{
    HCERTSTORE hStore = NULL;

    //Try to locate the appropriate store
    for (int i = 0;; i++)
    {
        if (hStore)
        {
            CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
            hStore = NULL;
        }

        RESULT_FIND_CERT_STORE resFnd = FindCertStoreByIndex(i, hStore, p7Data);
        if (resFnd == RESULT_FIND_CERT_STORE::RFCS_FOUND_ONE)
        {
            //Try to retrieve info
            if (PrintCertificateInformation(hStore, pSignerInfo, pStrCertDescription, bIsTimeStamp, pftTimeStampUtc) == RESULT_FIND_CONTEXT::RFC_FOUND_CONTEXT)
            {
                //All done
                break;
            }
        }
        else
        {
            //Stop the seatch
            if (resFnd == RESULT_FIND_CERT_STORE::RFCS_NONE)
            {
                std::ostringstream ss;
                ss << std::hex << ::GetLastError();
                std::string stringHex = ss.str();
                const std::wstring wsHex(stringHex.begin(), stringHex.end());

                //No context
                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CertOpenStore(no_context) failed: [0x" + wsHex + L"]\",";
            }
            else
            {
                std::ostringstream ss;
                ss << std::hex << ::GetLastError();
                std::string stringHex = ss.str();
                const std::wstring wsHex(stringHex.begin(), stringHex.end());

                //Error
                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CertOpenStore(%i) data failed: [0x" + wsHex + L"]\",";
            }

            break;
        }
    }


    if (hStore)
    {
        ::CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
        hStore = NULL;
    }

}


void PrintDualSignatureInformation(PCMSG_SIGNER_INFO pSignerInfo)
{
    //Loop through unauthenticated attributes
    for (DWORD a = 0; a < pSignerInfo->UnauthAttrs.cAttr; a++)
    {
#ifndef szOID_NESTED_SIGNATURE
#define szOID_NESTED_SIGNATURE              "1.3.6.1.4.1.311.2.4.1"
#endif

        //We need szOID_NESTED_SIGNATURE att
        if (pSignerInfo->UnauthAttrs.rgAttr[a].pszObjId &&
            lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[a].pszObjId, szOID_NESTED_SIGNATURE) == 0)
        {
            HCRYPTMSG hMsg = ::CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, NULL, NULL, NULL);
            if (hMsg)
            {
                if (::CryptMsgUpdate(hMsg,
                    pSignerInfo->UnauthAttrs.rgAttr[a].rgValue->pbData,
                    pSignerInfo->UnauthAttrs.rgAttr[a].rgValue->cbData,
                    TRUE))
                {
                    DWORD dwSignerInfo = 0;
                    ::CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
                    if (dwSignerInfo != 0)
                    {
                        PCMSG_SIGNER_INFO pSignerInfo2 = (PCMSG_SIGNER_INFO)new (std::nothrow) BYTE[dwSignerInfo];
                        if (pSignerInfo2)
                        {
                            if (::CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM,
                                0, (PVOID)pSignerInfo2, &dwSignerInfo))
                            {
                                CRYPT_DATA_BLOB c7Data;
                                c7Data.cbData = pSignerInfo->UnauthAttrs.rgAttr[a].rgValue->cbData;
                                c7Data.pbData = pSignerInfo->UnauthAttrs.rgAttr[a].rgValue->pbData;

                                //Try to locate the appropriate store & print from it
                                FindAppropriateStoreAndPrintCertificateInformation(pSignerInfo2, &c7Data, L"Dual Signer Certificate", FALSE);
                            }
                            else
                            {
                                std::ostringstream ss;
                                ss << std::hex << ::GetLastError();
                                std::string stringHex = ss.str();
                                const std::wstring wsHex(stringHex.begin(), stringHex.end());

                                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) data failed: [0x" + wsHex + L"]\",";
                            }

                            //Free mem
                            delete[] pSignerInfo2;
                            pSignerInfo2 = NULL;
                        }
                        else
                        {
                            std::ostringstream ss;
                            ss << std::hex << ::GetLastError();
                            std::string stringHex = ss.str();
                            const std::wstring wsHex(stringHex.begin(), stringHex.end());

                            global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"new(PCMSG_SIGNER_INFO) failed: [0x" + wsHex + L"]\",";
                        }
                    }
                    else
                    {
                        std::ostringstream ss;
                        ss << std::hex << ::GetLastError();
                        std::string stringHex = ss.str();
                        const std::wstring wsHex(stringHex.begin(), stringHex.end());

                        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) failed: [0x" + wsHex + L"]\",";
                    }
                }
                else
                {
                    std::ostringstream ss;
                    ss << std::hex << ::GetLastError();
                    std::string stringHex = ss.str();
                    const std::wstring wsHex(stringHex.begin(), stringHex.end());

                    global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptMsgUpdate(dual-sig) failed: [0x" + wsHex + L"]\",";
                }

                //Close message
                ::CryptMsgClose(hMsg);
            }
            else
            {
                std::ostringstream ss;
                ss << std::hex << ::GetLastError();
                std::string stringHex = ss.str();
                const std::wstring wsHex(stringHex.begin(), stringHex.end());

                global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) failed: [0x" + wsHex + L"]\",";
            }
        }
    }
}


BOOL VerifyWithWINTRUST(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;
    BOOL b_isPASS;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);

    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        b_isPASS = true;
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            b_isPASS = false;
            global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"The file is not signed.\",";
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            b_isPASS = false;
            global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"An unknown error occurred trying to verify the signature of the file.\",";
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        b_isPASS = false;
        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"The signature is present, but specifically disallowed by the admin or user.\",";
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        b_isPASS = false;
        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"The signature is present, but not trusted.\",";
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        b_isPASS = false;
        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"CRYPT_E_SECURITY_SETTINGS - The hash representing the subject or the publisher wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors.\",";
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        wprintf_s(L"Error is: 0x%x.\n",
            lStatus);
        wprintf_s(L"The file \"%s\" was analyzed.\n", pwszSourceFile);
        b_isPASS = false;
        global_result = global_result + L" \"ERROR-ENCOUNTERED\": \"Error is encountered in verifying the signature of the file.\",";
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    if (b_isPASS)
    {
        return true;
    }
    else
    {
        return false;
    }
}