#ifndef POET_ENCLAVE_T_H__
#define POET_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "../../poet_shared/poet.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


poet_err_t ecall_Initialize(sgx_ra_context_t* p_context);
poet_err_t ecall_CreateErsatzEnclaveReport(sgx_target_info_t* targetInfo, sgx_report_t* outReport);
poet_err_t ecall_GetPseManifestHash(sgx_sha256_hash_t* outPseManifestHash);
poet_err_t ecall_CalculateSealedSignupDataSize(size_t* pSealedSignupDataSize);
poet_err_t ecall_CreateSignupData(const sgx_target_info_t* inTargetInfo, const char* inOriginatorPublicKeyHash, sgx_ec256_public_t* outPoetPublicKey, sgx_report_t* outEnclaveReport, uint8_t* outSealedSignupData, size_t inSealedSignupDataSize, sgx_ps_sec_prop_desc_t* outPseManifest);
poet_err_t ecall_UnsealSignupData(const uint8_t* inSealedSignupData, size_t inSealedSignupDataSize, sgx_ec256_public_t* outPoetPublicKey);
poet_err_t ecall_ReleaseSignupData(const uint8_t* inSealedSignupData, size_t inSealedSignupDataSize);
poet_err_t ecall_VerifySignupInfo(const sgx_target_info_t* inTargetInfo, const char* inOriginatorPublicKeyHash, const sgx_ec256_public_t* inPoetPublicKey, const sgx_sha256_hash_t* inPseManifestHash, sgx_report_t* outEnclaveReport);
poet_err_t ecall_CreateWaitTimer(const uint8_t* inSealedSignupData, size_t inSealedSignupDataSize, const char* inValidatorAddress, const char* inPreviousCertificateId, double inRequestTime, double inLocalMean, double inMinimumWaitTime, char* outSerializedTimer, size_t inSerializedTimerLength, sgx_ec256_signature_t* outTimerSignature);
poet_err_t ecall_CreateWaitCertificate(const uint8_t* inSealedSignupData, size_t inSealedSignupDataSize, const char* inSerializedWaitTimer, const sgx_ec256_signature_t* inWaitTimerSignature, const char* inBlockHash, char* outSerializedWaitCertificate, size_t inSerializedWaitCertificateLength, sgx_ec256_signature_t* outWaitCertificateSignature);
poet_err_t ecall_VerifyWaitCertificate(const char* inSerializedWaitCertificate, const sgx_ec256_signature_t* inWaitCertificateSignature, const sgx_ec256_public_t* inPoetPublicKey);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_Print(const char* str);
sgx_status_t SGX_CDECL ocall_Log(int level, const char* str);
sgx_status_t SGX_CDECL ocall_SetErrorMessage(const char* msg);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
