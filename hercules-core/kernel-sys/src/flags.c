/* Exposes the pinned release's own script-verify constants (macros in
 * bitcoinkernel.h) as data symbols, so Rust tests compare our flag table
 * against the header actually compiled in, not a hand transcription. */
#include <bitcoinkernel.h>

const uint32_t hercules_btck_flag_none = btck_ScriptVerificationFlags_NONE;
const uint32_t hercules_btck_flag_p2sh = btck_ScriptVerificationFlags_P2SH;
const uint32_t hercules_btck_flag_dersig = btck_ScriptVerificationFlags_DERSIG;
const uint32_t hercules_btck_flag_nulldummy = btck_ScriptVerificationFlags_NULLDUMMY;
const uint32_t hercules_btck_flag_checklocktimeverify = btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY;
const uint32_t hercules_btck_flag_checksequenceverify = btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY;
const uint32_t hercules_btck_flag_witness = btck_ScriptVerificationFlags_WITNESS;
const uint32_t hercules_btck_flag_taproot = btck_ScriptVerificationFlags_TAPROOT;
const uint32_t hercules_btck_flag_all = btck_ScriptVerificationFlags_ALL;

const uint8_t hercules_btck_status_ok = btck_ScriptVerifyStatus_OK;
const uint8_t hercules_btck_status_invalid_flags_combination = btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION;
const uint8_t hercules_btck_status_spent_outputs_required = btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED;
