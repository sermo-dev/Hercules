// Hercules (ticket 053): script verification under Bitcoin Core's relay
// policy flags (STANDARD_SCRIPT_VERIFY_FLAGS), which the libbitcoinconsensus
// C API refuses (it takes the seven consensus flags only).
//
// The mempool runs this pass before the consensus one, as Core's
// PolicyScriptChecks runs before ConsensusScriptChecks, so neither our own
// sends nor relayed transactions get in with a script that peers refuse to
// relay (high-S, non-strict DER, NULLFAIL, CLEANSTACK, upgradable witness
// programs, ...). Exported with the `bitcoinconsensus_` prefix so the
// sealed Apple build (build.rs `seal_archives`) keeps it visible.
//
// The v26 interpreter's flag set and bit values are the same as the Core
// release libbitcoinkernel is built from (v32), and so is its behaviour
// under them except for pay-to-anchor (Core 28), handled below; the rest
// of the v26..v32 interpreter diff is error codes and refactoring. The
// Rust tests check `bitcoinconsensus_hercules_standard_flags` against
// hercules-core's table and run Core's script vectors under all flags.

#include <script/bitcoinconsensus.h>

#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <version.h>

#include <cstring>
#include <string>

namespace {

/** Deserializes one CTransaction (as bitcoinconsensus.cpp's TxInputStream). */
class PolicyTxInputStream
{
public:
    PolicyTxInputStream(int nVersionIn, const unsigned char* txTo, size_t txToLen)
        : m_version(nVersionIn), m_data(txTo), m_remaining(txToLen) {}

    void read(Span<std::byte> dst)
    {
        if (dst.size() > m_remaining) {
            throw std::ios_base::failure(std::string(__func__) + ": end of data");
        }
        if (dst.data() == nullptr || m_data == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad buffer");
        }
        memcpy(dst.data(), m_data, dst.size());
        m_remaining -= dst.size();
        m_data += dst.size();
    }

    template <typename T>
    PolicyTxInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

    int GetVersion() const { return m_version; }

private:
    const int m_version;
    const unsigned char* m_data;
    size_t m_remaining;
};

/** Core's STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h), by name. */
constexpr unsigned int STANDARD_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE | SCRIPT_VERIFY_CONST_SCRIPTCODE |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;

/** Every flag this interpreter knows: the bits below the highest one
 *  (SCRIPT_VERIFY_END_MARKER is that bit plus one). */
constexpr unsigned int ALL_FLAGS = ((SCRIPT_VERIFY_END_MARKER - 1) << 1) - 1;
static_assert(ALL_FLAGS == (1U << 21) - 1, "v26 has 21 script flags");

int fail(bitcoinconsensus_error* ret, bitcoinconsensus_error e)
{
    if (ret) *ret = e;
    return 0;
}

} // namespace

extern "C" {

unsigned int bitcoinconsensus_hercules_standard_flags()
{
    return STANDARD_FLAGS;
}

/** Like bitcoinconsensus_verify_script_with_spent_outputs, but with any of
 *  the interpreter's flags, and the ScriptError written to `script_error`
 *  (SCRIPT_ERR_OK unless the script failed). `spentOutputs` is required. */
int bitcoinconsensus_hercules_verify_script_policy(
    const unsigned char* scriptPubKey, unsigned int scriptPubKeyLen, int64_t amount,
    const unsigned char* txTo, unsigned int txToLen,
    const UTXO* spentOutputs, unsigned int spentOutputsLen,
    unsigned int nIn, unsigned int flags, bitcoinconsensus_error* err, int* script_error)
{
    if (script_error) *script_error = SCRIPT_ERR_OK;
    // VerifyScript asserts these combinations rather than refusing them.
    if ((flags & ~ALL_FLAGS) != 0 ||
        ((flags & SCRIPT_VERIFY_WITNESS) && !(flags & SCRIPT_VERIFY_P2SH)) ||
        ((flags & SCRIPT_VERIFY_CLEANSTACK) && !((flags & SCRIPT_VERIFY_P2SH) && (flags & SCRIPT_VERIFY_WITNESS)))) {
        return fail(err, bitcoinconsensus_ERR_INVALID_FLAGS);
    }
    if (spentOutputs == nullptr) {
        return fail(err, bitcoinconsensus_ERR_SPENT_OUTPUTS_REQUIRED);
    }
    try {
        PolicyTxInputStream stream(PROTOCOL_VERSION, txTo, txToLen);
        CTransaction tx(deserialize, stream);
        if (spentOutputsLen != tx.vin.size()) {
            return fail(err, bitcoinconsensus_ERR_SPENT_OUTPUTS_MISMATCH);
        }
        if (nIn >= tx.vin.size()) return fail(err, bitcoinconsensus_ERR_TX_INDEX);
        if (GetSerializeSize(tx, PROTOCOL_VERSION) != txToLen) {
            return fail(err, bitcoinconsensus_ERR_TX_SIZE_MISMATCH);
        }
        std::vector<CTxOut> spent_outputs;
        for (size_t i = 0; i < spentOutputsLen; i++) {
            CScript spk(spentOutputs[i].scriptPubKey, spentOutputs[i].scriptPubKey + spentOutputs[i].scriptPubKeySize);
            spent_outputs.emplace_back(spentOutputs[i].value, spk);
        }
        if (err) *err = bitcoinconsensus_ERR_OK;
        // The one script rule newer than v26 (Core 28's pay-to-anchor):
        // VerifyWitnessProgram accepts a native P2A spend
        // (`!is_p2sh && IsPayToAnchor`) before it would refuse an unknown
        // witness program under DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.
        // Without that flag v26 accepts the same spend the same way, so
        // clear it for that input. (Witness stuffing on a P2A spend is
        // IsWitnessStandard's, in hercules-core.)
        const CScript spk_script(scriptPubKey, scriptPubKey + scriptPubKeyLen);
        if (spk_script.size() == 4 && spk_script[0] == OP_1 && spk_script[1] == 0x02 &&
            spk_script[2] == 0x4e && spk_script[3] == 0x73) {
            flags &= ~static_cast<unsigned int>(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
        }
        PrecomputedTransactionData txdata(tx);
        txdata.Init(tx, std::move(spent_outputs));
        ScriptError serror = SCRIPT_ERR_OK;
        bool ok = VerifyScript(tx.vin[nIn].scriptSig, CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen),
                               &tx.vin[nIn].scriptWitness, flags,
                               TransactionSignatureChecker(&tx, nIn, CAmount(amount), txdata, MissingDataBehavior::FAIL),
                               &serror);
        if (script_error) *script_error = serror;
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        return fail(err, bitcoinconsensus_ERR_TX_DESERIALIZE);
    }
}

/** Core's ScriptErrorString for `script_error`, NUL-terminated into `buf`
 *  (truncated to `len`). Returns the full length. */
unsigned int bitcoinconsensus_hercules_script_error_string(int script_error, char* buf, unsigned int len)
{
    const std::string s = ScriptErrorString(static_cast<ScriptError>(script_error));
    if (buf && len > 0) {
        const size_t n = std::min<size_t>(s.size(), len - 1);
        memcpy(buf, s.data(), n);
        buf[n] = '\0';
    }
    return static_cast<unsigned int>(s.size());
}

} // extern "C"
