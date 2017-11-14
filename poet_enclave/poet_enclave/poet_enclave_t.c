#include "poet_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_Initialize_t {
	poet_err_t ms_retval;
	sgx_ra_context_t* ms_p_context;
} ms_ecall_Initialize_t;

typedef struct ms_ecall_CreateErsatzEnclaveReport_t {
	poet_err_t ms_retval;
	sgx_target_info_t* ms_targetInfo;
	sgx_report_t* ms_outReport;
} ms_ecall_CreateErsatzEnclaveReport_t;

typedef struct ms_ecall_GetPseManifestHash_t {
	poet_err_t ms_retval;
	sgx_sha256_hash_t* ms_outPseManifestHash;
} ms_ecall_GetPseManifestHash_t;

typedef struct ms_ecall_CalculateSealedSignupDataSize_t {
	poet_err_t ms_retval;
	size_t* ms_pSealedSignupDataSize;
} ms_ecall_CalculateSealedSignupDataSize_t;

typedef struct ms_ecall_CreateSignupData_t {
	poet_err_t ms_retval;
	sgx_target_info_t* ms_inTargetInfo;
	char* ms_inOriginatorPublicKeyHash;
	sgx_ec256_public_t* ms_outPoetPublicKey;
	sgx_report_t* ms_outEnclaveReport;
	uint8_t* ms_outSealedSignupData;
	size_t ms_inSealedSignupDataSize;
	sgx_ps_sec_prop_desc_t* ms_outPseManifest;
} ms_ecall_CreateSignupData_t;

typedef struct ms_ecall_UnsealSignupData_t {
	poet_err_t ms_retval;
	uint8_t* ms_inSealedSignupData;
	size_t ms_inSealedSignupDataSize;
	sgx_ec256_public_t* ms_outPoetPublicKey;
} ms_ecall_UnsealSignupData_t;

typedef struct ms_ecall_ReleaseSignupData_t {
	poet_err_t ms_retval;
	uint8_t* ms_inSealedSignupData;
	size_t ms_inSealedSignupDataSize;
} ms_ecall_ReleaseSignupData_t;

typedef struct ms_ecall_VerifySignupInfo_t {
	poet_err_t ms_retval;
	sgx_target_info_t* ms_inTargetInfo;
	char* ms_inOriginatorPublicKeyHash;
	sgx_ec256_public_t* ms_inPoetPublicKey;
	sgx_sha256_hash_t* ms_inPseManifestHash;
	sgx_report_t* ms_outEnclaveReport;
} ms_ecall_VerifySignupInfo_t;

typedef struct ms_ecall_CreateWaitTimer_t {
	poet_err_t ms_retval;
	uint8_t* ms_inSealedSignupData;
	size_t ms_inSealedSignupDataSize;
	char* ms_inValidatorAddress;
	char* ms_inPreviousCertificateId;
	double ms_inRequestTime;
	double ms_inLocalMean;
	double ms_inMinimumWaitTime;
	char* ms_outSerializedTimer;
	size_t ms_inSerializedTimerLength;
	sgx_ec256_signature_t* ms_outTimerSignature;
} ms_ecall_CreateWaitTimer_t;

typedef struct ms_ecall_CreateWaitCertificate_t {
	poet_err_t ms_retval;
	uint8_t* ms_inSealedSignupData;
	size_t ms_inSealedSignupDataSize;
	char* ms_inSerializedWaitTimer;
	sgx_ec256_signature_t* ms_inWaitTimerSignature;
	char* ms_inBlockHash;
	char* ms_outSerializedWaitCertificate;
	size_t ms_inSerializedWaitCertificateLength;
	sgx_ec256_signature_t* ms_outWaitCertificateSignature;
} ms_ecall_CreateWaitCertificate_t;

typedef struct ms_ecall_VerifyWaitCertificate_t {
	poet_err_t ms_retval;
	char* ms_inSerializedWaitCertificate;
	sgx_ec256_signature_t* ms_inWaitCertificateSignature;
	sgx_ec256_public_t* ms_inPoetPublicKey;
} ms_ecall_VerifyWaitCertificate_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_Print_t {
	char* ms_str;
} ms_ocall_Print_t;

typedef struct ms_ocall_Log_t {
	int ms_level;
	char* ms_str;
} ms_ocall_Log_t;

typedef struct ms_ocall_SetErrorMessage_t {
	char* ms_msg;
} ms_ocall_SetErrorMessage_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_Initialize(void* pms)
{
	ms_ecall_Initialize_t* ms = SGX_CAST(ms_ecall_Initialize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(*_tmp_p_context);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_Initialize_t));
	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	if (_tmp_p_context != NULL) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	ms->ms_retval = ecall_Initialize(_in_p_context);
err:
	if (_in_p_context) {
		memcpy(_tmp_p_context, _in_p_context, _len_p_context);
		free(_in_p_context);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_CreateErsatzEnclaveReport(void* pms)
{
	ms_ecall_CreateErsatzEnclaveReport_t* ms = SGX_CAST(ms_ecall_CreateErsatzEnclaveReport_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_targetInfo = ms->ms_targetInfo;
	size_t _len_targetInfo = sizeof(*_tmp_targetInfo);
	sgx_target_info_t* _in_targetInfo = NULL;
	sgx_report_t* _tmp_outReport = ms->ms_outReport;
	size_t _len_outReport = sizeof(*_tmp_outReport);
	sgx_report_t* _in_outReport = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_CreateErsatzEnclaveReport_t));
	CHECK_UNIQUE_POINTER(_tmp_targetInfo, _len_targetInfo);
	CHECK_UNIQUE_POINTER(_tmp_outReport, _len_outReport);

	if (_tmp_targetInfo != NULL) {
		_in_targetInfo = (sgx_target_info_t*)malloc(_len_targetInfo);
		if (_in_targetInfo == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_targetInfo, _tmp_targetInfo, _len_targetInfo);
	}
	if (_tmp_outReport != NULL) {
		if ((_in_outReport = (sgx_report_t*)malloc(_len_outReport)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outReport, 0, _len_outReport);
	}
	ms->ms_retval = ecall_CreateErsatzEnclaveReport(_in_targetInfo, _in_outReport);
err:
	if (_in_targetInfo) {
		memcpy(_tmp_targetInfo, _in_targetInfo, _len_targetInfo);
		free(_in_targetInfo);
	}
	if (_in_outReport) {
		memcpy(_tmp_outReport, _in_outReport, _len_outReport);
		free(_in_outReport);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_GetPseManifestHash(void* pms)
{
	ms_ecall_GetPseManifestHash_t* ms = SGX_CAST(ms_ecall_GetPseManifestHash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sha256_hash_t* _tmp_outPseManifestHash = ms->ms_outPseManifestHash;
	size_t _len_outPseManifestHash = sizeof(*_tmp_outPseManifestHash);
	sgx_sha256_hash_t* _in_outPseManifestHash = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_GetPseManifestHash_t));
	CHECK_UNIQUE_POINTER(_tmp_outPseManifestHash, _len_outPseManifestHash);

	if (_tmp_outPseManifestHash != NULL) {
		if ((_in_outPseManifestHash = (sgx_sha256_hash_t*)malloc(_len_outPseManifestHash)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outPseManifestHash, 0, _len_outPseManifestHash);
	}
	ms->ms_retval = ecall_GetPseManifestHash(_in_outPseManifestHash);
err:
	if (_in_outPseManifestHash) {
		memcpy(_tmp_outPseManifestHash, _in_outPseManifestHash, _len_outPseManifestHash);
		free(_in_outPseManifestHash);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_CalculateSealedSignupDataSize(void* pms)
{
	ms_ecall_CalculateSealedSignupDataSize_t* ms = SGX_CAST(ms_ecall_CalculateSealedSignupDataSize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_pSealedSignupDataSize = ms->ms_pSealedSignupDataSize;
	size_t _len_pSealedSignupDataSize = sizeof(*_tmp_pSealedSignupDataSize);
	size_t* _in_pSealedSignupDataSize = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_CalculateSealedSignupDataSize_t));
	CHECK_UNIQUE_POINTER(_tmp_pSealedSignupDataSize, _len_pSealedSignupDataSize);

	if (_tmp_pSealedSignupDataSize != NULL) {
		if ((_in_pSealedSignupDataSize = (size_t*)malloc(_len_pSealedSignupDataSize)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pSealedSignupDataSize, 0, _len_pSealedSignupDataSize);
	}
	ms->ms_retval = ecall_CalculateSealedSignupDataSize(_in_pSealedSignupDataSize);
err:
	if (_in_pSealedSignupDataSize) {
		memcpy(_tmp_pSealedSignupDataSize, _in_pSealedSignupDataSize, _len_pSealedSignupDataSize);
		free(_in_pSealedSignupDataSize);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_CreateSignupData(void* pms)
{
	ms_ecall_CreateSignupData_t* ms = SGX_CAST(ms_ecall_CreateSignupData_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_inTargetInfo = ms->ms_inTargetInfo;
	size_t _len_inTargetInfo = sizeof(*_tmp_inTargetInfo);
	sgx_target_info_t* _in_inTargetInfo = NULL;
	char* _tmp_inOriginatorPublicKeyHash = ms->ms_inOriginatorPublicKeyHash;
	size_t _len_inOriginatorPublicKeyHash = _tmp_inOriginatorPublicKeyHash ? strlen(_tmp_inOriginatorPublicKeyHash) + 1 : 0;
	char* _in_inOriginatorPublicKeyHash = NULL;
	sgx_ec256_public_t* _tmp_outPoetPublicKey = ms->ms_outPoetPublicKey;
	size_t _len_outPoetPublicKey = sizeof(*_tmp_outPoetPublicKey);
	sgx_ec256_public_t* _in_outPoetPublicKey = NULL;
	sgx_report_t* _tmp_outEnclaveReport = ms->ms_outEnclaveReport;
	size_t _len_outEnclaveReport = sizeof(*_tmp_outEnclaveReport);
	sgx_report_t* _in_outEnclaveReport = NULL;
	uint8_t* _tmp_outSealedSignupData = ms->ms_outSealedSignupData;
	size_t _tmp_inSealedSignupDataSize = ms->ms_inSealedSignupDataSize;
	size_t _len_outSealedSignupData = _tmp_inSealedSignupDataSize;
	uint8_t* _in_outSealedSignupData = NULL;
	sgx_ps_sec_prop_desc_t* _tmp_outPseManifest = ms->ms_outPseManifest;
	size_t _len_outPseManifest = sizeof(*_tmp_outPseManifest);
	sgx_ps_sec_prop_desc_t* _in_outPseManifest = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_CreateSignupData_t));
	CHECK_UNIQUE_POINTER(_tmp_inTargetInfo, _len_inTargetInfo);
	CHECK_UNIQUE_POINTER(_tmp_inOriginatorPublicKeyHash, _len_inOriginatorPublicKeyHash);
	CHECK_UNIQUE_POINTER(_tmp_outPoetPublicKey, _len_outPoetPublicKey);
	CHECK_UNIQUE_POINTER(_tmp_outEnclaveReport, _len_outEnclaveReport);
	CHECK_UNIQUE_POINTER(_tmp_outSealedSignupData, _len_outSealedSignupData);
	CHECK_UNIQUE_POINTER(_tmp_outPseManifest, _len_outPseManifest);

	if (_tmp_inTargetInfo != NULL) {
		_in_inTargetInfo = (sgx_target_info_t*)malloc(_len_inTargetInfo);
		if (_in_inTargetInfo == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inTargetInfo, _tmp_inTargetInfo, _len_inTargetInfo);
	}
	if (_tmp_inOriginatorPublicKeyHash != NULL) {
		_in_inOriginatorPublicKeyHash = (char*)malloc(_len_inOriginatorPublicKeyHash);
		if (_in_inOriginatorPublicKeyHash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inOriginatorPublicKeyHash, _tmp_inOriginatorPublicKeyHash, _len_inOriginatorPublicKeyHash);
		_in_inOriginatorPublicKeyHash[_len_inOriginatorPublicKeyHash - 1] = '\0';
	}
	if (_tmp_outPoetPublicKey != NULL) {
		if ((_in_outPoetPublicKey = (sgx_ec256_public_t*)malloc(_len_outPoetPublicKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outPoetPublicKey, 0, _len_outPoetPublicKey);
	}
	if (_tmp_outEnclaveReport != NULL) {
		if ((_in_outEnclaveReport = (sgx_report_t*)malloc(_len_outEnclaveReport)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outEnclaveReport, 0, _len_outEnclaveReport);
	}
	if (_tmp_outSealedSignupData != NULL) {
		if ((_in_outSealedSignupData = (uint8_t*)malloc(_len_outSealedSignupData)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outSealedSignupData, 0, _len_outSealedSignupData);
	}
	if (_tmp_outPseManifest != NULL) {
		if ((_in_outPseManifest = (sgx_ps_sec_prop_desc_t*)malloc(_len_outPseManifest)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outPseManifest, 0, _len_outPseManifest);
	}
	ms->ms_retval = ecall_CreateSignupData((const sgx_target_info_t*)_in_inTargetInfo, (const char*)_in_inOriginatorPublicKeyHash, _in_outPoetPublicKey, _in_outEnclaveReport, _in_outSealedSignupData, _tmp_inSealedSignupDataSize, _in_outPseManifest);
err:
	if (_in_inTargetInfo) free((void*)_in_inTargetInfo);
	if (_in_inOriginatorPublicKeyHash) free((void*)_in_inOriginatorPublicKeyHash);
	if (_in_outPoetPublicKey) {
		memcpy(_tmp_outPoetPublicKey, _in_outPoetPublicKey, _len_outPoetPublicKey);
		free(_in_outPoetPublicKey);
	}
	if (_in_outEnclaveReport) {
		memcpy(_tmp_outEnclaveReport, _in_outEnclaveReport, _len_outEnclaveReport);
		free(_in_outEnclaveReport);
	}
	if (_in_outSealedSignupData) {
		memcpy(_tmp_outSealedSignupData, _in_outSealedSignupData, _len_outSealedSignupData);
		free(_in_outSealedSignupData);
	}
	if (_in_outPseManifest) {
		memcpy(_tmp_outPseManifest, _in_outPseManifest, _len_outPseManifest);
		free(_in_outPseManifest);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_UnsealSignupData(void* pms)
{
	ms_ecall_UnsealSignupData_t* ms = SGX_CAST(ms_ecall_UnsealSignupData_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_inSealedSignupData = ms->ms_inSealedSignupData;
	size_t _tmp_inSealedSignupDataSize = ms->ms_inSealedSignupDataSize;
	size_t _len_inSealedSignupData = _tmp_inSealedSignupDataSize;
	uint8_t* _in_inSealedSignupData = NULL;
	sgx_ec256_public_t* _tmp_outPoetPublicKey = ms->ms_outPoetPublicKey;
	size_t _len_outPoetPublicKey = sizeof(*_tmp_outPoetPublicKey);
	sgx_ec256_public_t* _in_outPoetPublicKey = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_UnsealSignupData_t));
	CHECK_UNIQUE_POINTER(_tmp_inSealedSignupData, _len_inSealedSignupData);
	CHECK_UNIQUE_POINTER(_tmp_outPoetPublicKey, _len_outPoetPublicKey);

	if (_tmp_inSealedSignupData != NULL) {
		_in_inSealedSignupData = (uint8_t*)malloc(_len_inSealedSignupData);
		if (_in_inSealedSignupData == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inSealedSignupData, _tmp_inSealedSignupData, _len_inSealedSignupData);
	}
	if (_tmp_outPoetPublicKey != NULL) {
		if ((_in_outPoetPublicKey = (sgx_ec256_public_t*)malloc(_len_outPoetPublicKey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outPoetPublicKey, 0, _len_outPoetPublicKey);
	}
	ms->ms_retval = ecall_UnsealSignupData((const uint8_t*)_in_inSealedSignupData, _tmp_inSealedSignupDataSize, _in_outPoetPublicKey);
err:
	if (_in_inSealedSignupData) free((void*)_in_inSealedSignupData);
	if (_in_outPoetPublicKey) {
		memcpy(_tmp_outPoetPublicKey, _in_outPoetPublicKey, _len_outPoetPublicKey);
		free(_in_outPoetPublicKey);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ReleaseSignupData(void* pms)
{
	ms_ecall_ReleaseSignupData_t* ms = SGX_CAST(ms_ecall_ReleaseSignupData_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_inSealedSignupData = ms->ms_inSealedSignupData;
	size_t _tmp_inSealedSignupDataSize = ms->ms_inSealedSignupDataSize;
	size_t _len_inSealedSignupData = _tmp_inSealedSignupDataSize;
	uint8_t* _in_inSealedSignupData = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ReleaseSignupData_t));
	CHECK_UNIQUE_POINTER(_tmp_inSealedSignupData, _len_inSealedSignupData);

	if (_tmp_inSealedSignupData != NULL) {
		_in_inSealedSignupData = (uint8_t*)malloc(_len_inSealedSignupData);
		if (_in_inSealedSignupData == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inSealedSignupData, _tmp_inSealedSignupData, _len_inSealedSignupData);
	}
	ms->ms_retval = ecall_ReleaseSignupData((const uint8_t*)_in_inSealedSignupData, _tmp_inSealedSignupDataSize);
err:
	if (_in_inSealedSignupData) free((void*)_in_inSealedSignupData);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_VerifySignupInfo(void* pms)
{
	ms_ecall_VerifySignupInfo_t* ms = SGX_CAST(ms_ecall_VerifySignupInfo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_inTargetInfo = ms->ms_inTargetInfo;
	size_t _len_inTargetInfo = sizeof(*_tmp_inTargetInfo);
	sgx_target_info_t* _in_inTargetInfo = NULL;
	char* _tmp_inOriginatorPublicKeyHash = ms->ms_inOriginatorPublicKeyHash;
	size_t _len_inOriginatorPublicKeyHash = _tmp_inOriginatorPublicKeyHash ? strlen(_tmp_inOriginatorPublicKeyHash) + 1 : 0;
	char* _in_inOriginatorPublicKeyHash = NULL;
	sgx_ec256_public_t* _tmp_inPoetPublicKey = ms->ms_inPoetPublicKey;
	size_t _len_inPoetPublicKey = sizeof(*_tmp_inPoetPublicKey);
	sgx_ec256_public_t* _in_inPoetPublicKey = NULL;
	sgx_sha256_hash_t* _tmp_inPseManifestHash = ms->ms_inPseManifestHash;
	size_t _len_inPseManifestHash = sizeof(*_tmp_inPseManifestHash);
	sgx_sha256_hash_t* _in_inPseManifestHash = NULL;
	sgx_report_t* _tmp_outEnclaveReport = ms->ms_outEnclaveReport;
	size_t _len_outEnclaveReport = sizeof(*_tmp_outEnclaveReport);
	sgx_report_t* _in_outEnclaveReport = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_VerifySignupInfo_t));
	CHECK_UNIQUE_POINTER(_tmp_inTargetInfo, _len_inTargetInfo);
	CHECK_UNIQUE_POINTER(_tmp_inOriginatorPublicKeyHash, _len_inOriginatorPublicKeyHash);
	CHECK_UNIQUE_POINTER(_tmp_inPoetPublicKey, _len_inPoetPublicKey);
	CHECK_UNIQUE_POINTER(_tmp_inPseManifestHash, _len_inPseManifestHash);
	CHECK_UNIQUE_POINTER(_tmp_outEnclaveReport, _len_outEnclaveReport);

	if (_tmp_inTargetInfo != NULL) {
		_in_inTargetInfo = (sgx_target_info_t*)malloc(_len_inTargetInfo);
		if (_in_inTargetInfo == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inTargetInfo, _tmp_inTargetInfo, _len_inTargetInfo);
	}
	if (_tmp_inOriginatorPublicKeyHash != NULL) {
		_in_inOriginatorPublicKeyHash = (char*)malloc(_len_inOriginatorPublicKeyHash);
		if (_in_inOriginatorPublicKeyHash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inOriginatorPublicKeyHash, _tmp_inOriginatorPublicKeyHash, _len_inOriginatorPublicKeyHash);
		_in_inOriginatorPublicKeyHash[_len_inOriginatorPublicKeyHash - 1] = '\0';
	}
	if (_tmp_inPoetPublicKey != NULL) {
		_in_inPoetPublicKey = (sgx_ec256_public_t*)malloc(_len_inPoetPublicKey);
		if (_in_inPoetPublicKey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inPoetPublicKey, _tmp_inPoetPublicKey, _len_inPoetPublicKey);
	}
	if (_tmp_inPseManifestHash != NULL) {
		_in_inPseManifestHash = (sgx_sha256_hash_t*)malloc(_len_inPseManifestHash);
		if (_in_inPseManifestHash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inPseManifestHash, _tmp_inPseManifestHash, _len_inPseManifestHash);
	}
	if (_tmp_outEnclaveReport != NULL) {
		if ((_in_outEnclaveReport = (sgx_report_t*)malloc(_len_outEnclaveReport)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outEnclaveReport, 0, _len_outEnclaveReport);
	}
	ms->ms_retval = ecall_VerifySignupInfo((const sgx_target_info_t*)_in_inTargetInfo, (const char*)_in_inOriginatorPublicKeyHash, (const sgx_ec256_public_t*)_in_inPoetPublicKey, (const sgx_sha256_hash_t*)_in_inPseManifestHash, _in_outEnclaveReport);
err:
	if (_in_inTargetInfo) free((void*)_in_inTargetInfo);
	if (_in_inOriginatorPublicKeyHash) free((void*)_in_inOriginatorPublicKeyHash);
	if (_in_inPoetPublicKey) free((void*)_in_inPoetPublicKey);
	if (_in_inPseManifestHash) free((void*)_in_inPseManifestHash);
	if (_in_outEnclaveReport) {
		memcpy(_tmp_outEnclaveReport, _in_outEnclaveReport, _len_outEnclaveReport);
		free(_in_outEnclaveReport);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_CreateWaitTimer(void* pms)
{
	ms_ecall_CreateWaitTimer_t* ms = SGX_CAST(ms_ecall_CreateWaitTimer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_inSealedSignupData = ms->ms_inSealedSignupData;
	size_t _tmp_inSealedSignupDataSize = ms->ms_inSealedSignupDataSize;
	size_t _len_inSealedSignupData = _tmp_inSealedSignupDataSize;
	uint8_t* _in_inSealedSignupData = NULL;
	char* _tmp_inValidatorAddress = ms->ms_inValidatorAddress;
	size_t _len_inValidatorAddress = _tmp_inValidatorAddress ? strlen(_tmp_inValidatorAddress) + 1 : 0;
	char* _in_inValidatorAddress = NULL;
	char* _tmp_inPreviousCertificateId = ms->ms_inPreviousCertificateId;
	size_t _len_inPreviousCertificateId = _tmp_inPreviousCertificateId ? strlen(_tmp_inPreviousCertificateId) + 1 : 0;
	char* _in_inPreviousCertificateId = NULL;
	char* _tmp_outSerializedTimer = ms->ms_outSerializedTimer;
	size_t _tmp_inSerializedTimerLength = ms->ms_inSerializedTimerLength;
	size_t _len_outSerializedTimer = _tmp_inSerializedTimerLength;
	char* _in_outSerializedTimer = NULL;
	sgx_ec256_signature_t* _tmp_outTimerSignature = ms->ms_outTimerSignature;
	size_t _len_outTimerSignature = sizeof(*_tmp_outTimerSignature);
	sgx_ec256_signature_t* _in_outTimerSignature = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_CreateWaitTimer_t));
	CHECK_UNIQUE_POINTER(_tmp_inSealedSignupData, _len_inSealedSignupData);
	CHECK_UNIQUE_POINTER(_tmp_inValidatorAddress, _len_inValidatorAddress);
	CHECK_UNIQUE_POINTER(_tmp_inPreviousCertificateId, _len_inPreviousCertificateId);
	CHECK_UNIQUE_POINTER(_tmp_outSerializedTimer, _len_outSerializedTimer);
	CHECK_UNIQUE_POINTER(_tmp_outTimerSignature, _len_outTimerSignature);

	if (_tmp_inSealedSignupData != NULL) {
		_in_inSealedSignupData = (uint8_t*)malloc(_len_inSealedSignupData);
		if (_in_inSealedSignupData == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inSealedSignupData, _tmp_inSealedSignupData, _len_inSealedSignupData);
	}
	if (_tmp_inValidatorAddress != NULL) {
		_in_inValidatorAddress = (char*)malloc(_len_inValidatorAddress);
		if (_in_inValidatorAddress == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inValidatorAddress, _tmp_inValidatorAddress, _len_inValidatorAddress);
		_in_inValidatorAddress[_len_inValidatorAddress - 1] = '\0';
	}
	if (_tmp_inPreviousCertificateId != NULL) {
		_in_inPreviousCertificateId = (char*)malloc(_len_inPreviousCertificateId);
		if (_in_inPreviousCertificateId == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inPreviousCertificateId, _tmp_inPreviousCertificateId, _len_inPreviousCertificateId);
		_in_inPreviousCertificateId[_len_inPreviousCertificateId - 1] = '\0';
	}
	if (_tmp_outSerializedTimer != NULL) {
		if ((_in_outSerializedTimer = (char*)malloc(_len_outSerializedTimer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outSerializedTimer, 0, _len_outSerializedTimer);
	}
	if (_tmp_outTimerSignature != NULL) {
		if ((_in_outTimerSignature = (sgx_ec256_signature_t*)malloc(_len_outTimerSignature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outTimerSignature, 0, _len_outTimerSignature);
	}
	ms->ms_retval = ecall_CreateWaitTimer((const uint8_t*)_in_inSealedSignupData, _tmp_inSealedSignupDataSize, (const char*)_in_inValidatorAddress, (const char*)_in_inPreviousCertificateId, ms->ms_inRequestTime, ms->ms_inLocalMean, ms->ms_inMinimumWaitTime, _in_outSerializedTimer, _tmp_inSerializedTimerLength, _in_outTimerSignature);
err:
	if (_in_inSealedSignupData) free((void*)_in_inSealedSignupData);
	if (_in_inValidatorAddress) free((void*)_in_inValidatorAddress);
	if (_in_inPreviousCertificateId) free((void*)_in_inPreviousCertificateId);
	if (_in_outSerializedTimer) {
		memcpy(_tmp_outSerializedTimer, _in_outSerializedTimer, _len_outSerializedTimer);
		free(_in_outSerializedTimer);
	}
	if (_in_outTimerSignature) {
		memcpy(_tmp_outTimerSignature, _in_outTimerSignature, _len_outTimerSignature);
		free(_in_outTimerSignature);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_CreateWaitCertificate(void* pms)
{
	ms_ecall_CreateWaitCertificate_t* ms = SGX_CAST(ms_ecall_CreateWaitCertificate_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_inSealedSignupData = ms->ms_inSealedSignupData;
	size_t _tmp_inSealedSignupDataSize = ms->ms_inSealedSignupDataSize;
	size_t _len_inSealedSignupData = _tmp_inSealedSignupDataSize;
	uint8_t* _in_inSealedSignupData = NULL;
	char* _tmp_inSerializedWaitTimer = ms->ms_inSerializedWaitTimer;
	size_t _len_inSerializedWaitTimer = _tmp_inSerializedWaitTimer ? strlen(_tmp_inSerializedWaitTimer) + 1 : 0;
	char* _in_inSerializedWaitTimer = NULL;
	sgx_ec256_signature_t* _tmp_inWaitTimerSignature = ms->ms_inWaitTimerSignature;
	size_t _len_inWaitTimerSignature = sizeof(*_tmp_inWaitTimerSignature);
	sgx_ec256_signature_t* _in_inWaitTimerSignature = NULL;
	char* _tmp_inBlockHash = ms->ms_inBlockHash;
	size_t _len_inBlockHash = _tmp_inBlockHash ? strlen(_tmp_inBlockHash) + 1 : 0;
	char* _in_inBlockHash = NULL;
	char* _tmp_outSerializedWaitCertificate = ms->ms_outSerializedWaitCertificate;
	size_t _tmp_inSerializedWaitCertificateLength = ms->ms_inSerializedWaitCertificateLength;
	size_t _len_outSerializedWaitCertificate = _tmp_inSerializedWaitCertificateLength;
	char* _in_outSerializedWaitCertificate = NULL;
	sgx_ec256_signature_t* _tmp_outWaitCertificateSignature = ms->ms_outWaitCertificateSignature;
	size_t _len_outWaitCertificateSignature = sizeof(*_tmp_outWaitCertificateSignature);
	sgx_ec256_signature_t* _in_outWaitCertificateSignature = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_CreateWaitCertificate_t));
	CHECK_UNIQUE_POINTER(_tmp_inSealedSignupData, _len_inSealedSignupData);
	CHECK_UNIQUE_POINTER(_tmp_inSerializedWaitTimer, _len_inSerializedWaitTimer);
	CHECK_UNIQUE_POINTER(_tmp_inWaitTimerSignature, _len_inWaitTimerSignature);
	CHECK_UNIQUE_POINTER(_tmp_inBlockHash, _len_inBlockHash);
	CHECK_UNIQUE_POINTER(_tmp_outSerializedWaitCertificate, _len_outSerializedWaitCertificate);
	CHECK_UNIQUE_POINTER(_tmp_outWaitCertificateSignature, _len_outWaitCertificateSignature);

	if (_tmp_inSealedSignupData != NULL) {
		_in_inSealedSignupData = (uint8_t*)malloc(_len_inSealedSignupData);
		if (_in_inSealedSignupData == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inSealedSignupData, _tmp_inSealedSignupData, _len_inSealedSignupData);
	}
	if (_tmp_inSerializedWaitTimer != NULL) {
		_in_inSerializedWaitTimer = (char*)malloc(_len_inSerializedWaitTimer);
		if (_in_inSerializedWaitTimer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inSerializedWaitTimer, _tmp_inSerializedWaitTimer, _len_inSerializedWaitTimer);
		_in_inSerializedWaitTimer[_len_inSerializedWaitTimer - 1] = '\0';
	}
	if (_tmp_inWaitTimerSignature != NULL) {
		_in_inWaitTimerSignature = (sgx_ec256_signature_t*)malloc(_len_inWaitTimerSignature);
		if (_in_inWaitTimerSignature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inWaitTimerSignature, _tmp_inWaitTimerSignature, _len_inWaitTimerSignature);
	}
	if (_tmp_inBlockHash != NULL) {
		_in_inBlockHash = (char*)malloc(_len_inBlockHash);
		if (_in_inBlockHash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inBlockHash, _tmp_inBlockHash, _len_inBlockHash);
		_in_inBlockHash[_len_inBlockHash - 1] = '\0';
	}
	if (_tmp_outSerializedWaitCertificate != NULL) {
		if ((_in_outSerializedWaitCertificate = (char*)malloc(_len_outSerializedWaitCertificate)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outSerializedWaitCertificate, 0, _len_outSerializedWaitCertificate);
	}
	if (_tmp_outWaitCertificateSignature != NULL) {
		if ((_in_outWaitCertificateSignature = (sgx_ec256_signature_t*)malloc(_len_outWaitCertificateSignature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_outWaitCertificateSignature, 0, _len_outWaitCertificateSignature);
	}
	ms->ms_retval = ecall_CreateWaitCertificate((const uint8_t*)_in_inSealedSignupData, _tmp_inSealedSignupDataSize, (const char*)_in_inSerializedWaitTimer, (const sgx_ec256_signature_t*)_in_inWaitTimerSignature, (const char*)_in_inBlockHash, _in_outSerializedWaitCertificate, _tmp_inSerializedWaitCertificateLength, _in_outWaitCertificateSignature);
err:
	if (_in_inSealedSignupData) free((void*)_in_inSealedSignupData);
	if (_in_inSerializedWaitTimer) free((void*)_in_inSerializedWaitTimer);
	if (_in_inWaitTimerSignature) free((void*)_in_inWaitTimerSignature);
	if (_in_inBlockHash) free((void*)_in_inBlockHash);
	if (_in_outSerializedWaitCertificate) {
		memcpy(_tmp_outSerializedWaitCertificate, _in_outSerializedWaitCertificate, _len_outSerializedWaitCertificate);
		free(_in_outSerializedWaitCertificate);
	}
	if (_in_outWaitCertificateSignature) {
		memcpy(_tmp_outWaitCertificateSignature, _in_outWaitCertificateSignature, _len_outWaitCertificateSignature);
		free(_in_outWaitCertificateSignature);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_VerifyWaitCertificate(void* pms)
{
	ms_ecall_VerifyWaitCertificate_t* ms = SGX_CAST(ms_ecall_VerifyWaitCertificate_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_inSerializedWaitCertificate = ms->ms_inSerializedWaitCertificate;
	size_t _len_inSerializedWaitCertificate = _tmp_inSerializedWaitCertificate ? strlen(_tmp_inSerializedWaitCertificate) + 1 : 0;
	char* _in_inSerializedWaitCertificate = NULL;
	sgx_ec256_signature_t* _tmp_inWaitCertificateSignature = ms->ms_inWaitCertificateSignature;
	size_t _len_inWaitCertificateSignature = sizeof(*_tmp_inWaitCertificateSignature);
	sgx_ec256_signature_t* _in_inWaitCertificateSignature = NULL;
	sgx_ec256_public_t* _tmp_inPoetPublicKey = ms->ms_inPoetPublicKey;
	size_t _len_inPoetPublicKey = sizeof(*_tmp_inPoetPublicKey);
	sgx_ec256_public_t* _in_inPoetPublicKey = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_VerifyWaitCertificate_t));
	CHECK_UNIQUE_POINTER(_tmp_inSerializedWaitCertificate, _len_inSerializedWaitCertificate);
	CHECK_UNIQUE_POINTER(_tmp_inWaitCertificateSignature, _len_inWaitCertificateSignature);
	CHECK_UNIQUE_POINTER(_tmp_inPoetPublicKey, _len_inPoetPublicKey);

	if (_tmp_inSerializedWaitCertificate != NULL) {
		_in_inSerializedWaitCertificate = (char*)malloc(_len_inSerializedWaitCertificate);
		if (_in_inSerializedWaitCertificate == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inSerializedWaitCertificate, _tmp_inSerializedWaitCertificate, _len_inSerializedWaitCertificate);
		_in_inSerializedWaitCertificate[_len_inSerializedWaitCertificate - 1] = '\0';
	}
	if (_tmp_inWaitCertificateSignature != NULL) {
		_in_inWaitCertificateSignature = (sgx_ec256_signature_t*)malloc(_len_inWaitCertificateSignature);
		if (_in_inWaitCertificateSignature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inWaitCertificateSignature, _tmp_inWaitCertificateSignature, _len_inWaitCertificateSignature);
	}
	if (_tmp_inPoetPublicKey != NULL) {
		_in_inPoetPublicKey = (sgx_ec256_public_t*)malloc(_len_inPoetPublicKey);
		if (_in_inPoetPublicKey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_inPoetPublicKey, _tmp_inPoetPublicKey, _len_inPoetPublicKey);
	}
	ms->ms_retval = ecall_VerifyWaitCertificate((const char*)_in_inSerializedWaitCertificate, (const sgx_ec256_signature_t*)_in_inWaitCertificateSignature, (const sgx_ec256_public_t*)_in_inPoetPublicKey);
err:
	if (_in_inSerializedWaitCertificate) free((void*)_in_inSerializedWaitCertificate);
	if (_in_inWaitCertificateSignature) free((void*)_in_inWaitCertificateSignature);
	if (_in_inPoetPublicKey) free((void*)_in_inPoetPublicKey);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	if (_tmp_g_a != NULL) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		memcpy(_tmp_g_a, _in_g_a, _len_g_a);
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(*_tmp_p_msg2);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(*_tmp_p_qe_target);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(*_tmp_p_report);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(*_tmp_p_nonce);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	if (_tmp_p_msg2 != NULL) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_msg2, _tmp_p_msg2, _len_p_msg2);
	}
	if (_tmp_p_qe_target != NULL) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_qe_target, _tmp_p_qe_target, _len_p_qe_target);
	}
	if (_tmp_p_report != NULL) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free((void*)_in_p_msg2);
	if (_in_p_qe_target) free((void*)_in_p_qe_target);
	if (_in_p_report) {
		memcpy(_tmp_p_report, _in_p_report, _len_p_report);
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		memcpy(_tmp_p_nonce, _in_p_nonce, _len_p_nonce);
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(*_tmp_qe_report);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	if (_tmp_qe_report != NULL) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_qe_report, _tmp_qe_report, _len_qe_report);
	}
	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[14];
} g_ecall_table = {
	14,
	{
		{(void*)(uintptr_t)sgx_ecall_Initialize, 0},
		{(void*)(uintptr_t)sgx_ecall_CreateErsatzEnclaveReport, 0},
		{(void*)(uintptr_t)sgx_ecall_GetPseManifestHash, 0},
		{(void*)(uintptr_t)sgx_ecall_CalculateSealedSignupDataSize, 0},
		{(void*)(uintptr_t)sgx_ecall_CreateSignupData, 0},
		{(void*)(uintptr_t)sgx_ecall_UnsealSignupData, 0},
		{(void*)(uintptr_t)sgx_ecall_ReleaseSignupData, 0},
		{(void*)(uintptr_t)sgx_ecall_VerifySignupInfo, 0},
		{(void*)(uintptr_t)sgx_ecall_CreateWaitTimer, 0},
		{(void*)(uintptr_t)sgx_ecall_CreateWaitCertificate, 0},
		{(void*)(uintptr_t)sgx_ecall_VerifyWaitCertificate, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[12][14];
} g_dyn_entry_table = {
	12,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_Print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_Print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_Log(int level, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_Log_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Log_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Log_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Log_t));

	ms->ms_level = level;
	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_SetErrorMessage(const char* msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_msg = msg ? strlen(msg) + 1 : 0;

	ms_ocall_SetErrorMessage_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_SetErrorMessage_t);
	void *__tmp = NULL;

	ocalloc_size += (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) ? _len_msg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_SetErrorMessage_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_SetErrorMessage_t));

	if (msg != NULL && sgx_is_within_enclave(msg, _len_msg)) {
		ms->ms_msg = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_msg);
		memcpy((void*)ms->ms_msg, msg, _len_msg);
	} else if (msg == NULL) {
		ms->ms_msg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sid);
		memset(ms->ms_sid, 0, _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, ms->ms_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		memcpy(ms->ms_pse_message_req, pse_message_req, _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		memset(ms->ms_pse_message_resp, 0, _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, ms->ms_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(7, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
