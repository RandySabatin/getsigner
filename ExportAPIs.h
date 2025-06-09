#pragma once

#ifdef API_EXPORTS
#define EXPORT_API __declspec(dllexport)
#else
#define IMPORT_API __declspec(dllimport)
#endif


#ifdef __cplusplus
extern "C" {
#endif

    EXPORT_API int GetFileSignature(char* incoming, char* result, size_t resultMaxLength);
    EXPORT_API int DeleteBuffer(char* incoming, char* result, size_t resultMaxLength);

#ifdef __cplusplus
}
#endif

