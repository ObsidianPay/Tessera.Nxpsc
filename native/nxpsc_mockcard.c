//-----------------------------------------------------------------------------
// This file is part of Tessera.Nxpsc and is licensed under the GNU General
// Public License, version 3 or later. See LICENSE.
//-----------------------------------------------------------------------------
// nxpsc_mockcard - libnxpsc's mock card, with state
//
// libnxpsc's tests/mockcard.c speaks the real framing and runs the real card
// side crypto, but it is stateless about which key a card holds: libnxpsc's own
// tests set the key before every handshake. Driving a whole flow from .NET
// needs a card that remembers: the factory PICC key, the applications created,
// the keys changed. This keeps that state and hands mockcard.c the right key
// before each authentication.
//
// The host must use the fixed RndA mockcard.c expects (0x10, 0x11, ...), as
// libnxpsc's protocol tests do. Tessera.Nxpsc.MockCard arranges that.
//
// What it cannot witness: whether a ChangeKey cryptogram carried the intended
// key. Decoding it would mean a second secure messaging implementation. The
// caller states up front what a changed key reads as
// (mockcard_set_change_key_result). Proving a key really changed takes real
// hardware and an independent reader.
//-----------------------------------------------------------------------------

#include "mockcard.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define MOCKCARD_API __declspec(dllexport)
#else
#define MOCKCARD_API __attribute__((visibility("default")))
#endif

#define MOCKCARD_MAX_APPS  8
#define MOCKCARD_MAX_KEYS  14

typedef struct {
    bool present;
    uint32_t aid;
    uint8_t num_keys;
    nxpsc_keytype_t key_type[MOCKCARD_MAX_KEYS];
    uint8_t key[MOCKCARD_MAX_KEYS][NXPSC_MAX_KEY_SIZE];
} mockcard_app_t;

typedef struct {
    mock_card_t mock;

    // index 0 is the PICC (AID 000000), with one key: the PICC master key
    mockcard_app_t apps[MOCKCARD_MAX_APPS];

    bool change_takes;
    nxpsc_keytype_t change_type;
    uint8_t change_key[NXPSC_MAX_KEY_SIZE];

    uint8_t signature[56];
    bool has_signature;

    uint8_t tear_cmd;
    bool tear_after_execute;
    bool torn;                      // field gone, every exchange fails
} mockcard_t;

//-----------------------------------------------------------------------------
// state helpers
//-----------------------------------------------------------------------------
static mockcard_app_t *find_app(mockcard_t *t, uint32_t aid) {
    for (size_t i = 0; i < MOCKCARD_MAX_APPS; i++) {
        if (t->apps[i].present && t->apps[i].aid == aid) {
            return &t->apps[i];
        }
    }
    return NULL;
}

static mockcard_app_t *add_app(mockcard_t *t, uint32_t aid, nxpsc_keytype_t type, uint8_t num_keys) {
    if (num_keys == 0 || num_keys > MOCKCARD_MAX_KEYS) {
        return NULL;
    }
    for (size_t i = 0; i < MOCKCARD_MAX_APPS; i++) {
        if (t->apps[i].present == false) {
            memset(&t->apps[i], 0, sizeof(t->apps[i]));
            t->apps[i].present = true;
            t->apps[i].aid = aid;
            t->apps[i].num_keys = num_keys;
            for (uint8_t k = 0; k < num_keys; k++) {
                t->apps[i].key_type[k] = type;     // factory keys are all zero
            }
            return &t->apps[i];
        }
    }
    return NULL;
}

// the PICC drops secure messaging on select, and on a torn field
static void drop_session(mockcard_t *t) {
    t->mock.secure_active = false;
    t->mock.secure_cmd_ctr = 0;
    t->mock.auth_pending = false;
}

//-----------------------------------------------------------------------------
// framing. NXPSC_CMDSET_NATIVE_ISO frames are 90 cmd 00 00 [Lc data] 00 and
// answered data || 91 status; NXPSC_CMDSET_NATIVE frames are cmd || data and
// answered status || data. Real ISO 7816-4 commands (CLA 00) are not
// interpreted here and go straight to mockcard.c
//-----------------------------------------------------------------------------
static bool parse_frame(const uint8_t *tx, size_t tx_len, uint8_t *cmd,
                        const uint8_t **data, size_t *data_len, bool *wrapped) {
    *data = NULL;
    *data_len = 0;
    if (tx_len >= 5 && tx[0] == 0x90) {
        *wrapped = true;
        *cmd = tx[1];
        if (tx_len > 5) {
            *data = tx + 5;
            *data_len = tx[4];
        }
        return true;
    }
    if (tx_len >= 1 && tx[0] != 0x00) {
        *wrapped = false;
        *cmd = tx[0];
        if (tx_len > 1) {
            *data = tx + 1;
            *data_len = tx_len - 1;
        }
        return true;
    }
    return false;
}

static int status_only(bool wrapped, uint8_t status, uint8_t *rx, size_t cap, size_t *rx_len) {
    if (cap < 2) {
        return NXPSC_E_LENGTH;
    }
    if (wrapped) {
        rx[0] = 0x91;
        rx[1] = status;
        *rx_len = 2;
    } else {
        rx[0] = status;
        *rx_len = 1;
    }
    return NXPSC_OK;
}

static bool answered_ok(bool wrapped, const uint8_t *rx, size_t rx_len) {
    if (wrapped) {
        return rx_len >= 2 && rx[rx_len - 2] == 0x91 && rx[rx_len - 1] == 0x00;
    }
    return rx_len >= 1 && rx[0] == 0x00;
}

//-----------------------------------------------------------------------------
// exported surface
//-----------------------------------------------------------------------------
MOCKCARD_API mockcard_t *mockcard_create(int card_type, const uint8_t *uid, size_t uid_len) {
    mockcard_t *t = (mockcard_t *)calloc(1, sizeof(mockcard_t));
    if (t == NULL) {
        return NULL;
    }
    mock_init(&t->mock, (nxpsc_cardtype_t)card_type);
    if (uid != NULL && uid_len == sizeof(t->mock.uid)) {
        memcpy(t->mock.uid, uid, uid_len);
    }

    // factory state: the PICC master key is 2TDEA all zero
    mockcard_app_t *picc = add_app(t, 0x000000, NXPSC_KEY_2K3DES, 1);
    (void)picc;
    t->change_takes = false;
    return t;
}

MOCKCARD_API void mockcard_free(mockcard_t *t) {
    if (t != NULL) {
        memset(t, 0, sizeof(*t));
        free(t);
    }
}

// replace one key the card holds. aid 0 key 0 is the PICC master key
MOCKCARD_API int mockcard_set_key(mockcard_t *t, uint32_t aid, uint8_t key_no, int key_type,
                            const uint8_t *key, size_t key_len) {
    mockcard_app_t *app = find_app(t, aid);
    if (app == NULL || key_no >= app->num_keys || key_len > NXPSC_MAX_KEY_SIZE) {
        return NXPSC_E_PARAM;
    }
    app->key_type[key_no] = (nxpsc_keytype_t)key_type;
    memset(app->key[key_no], 0, NXPSC_MAX_KEY_SIZE);
    memcpy(app->key[key_no], key, key_len);
    return NXPSC_OK;
}

// an application that is already on the card, with all-zero keys
MOCKCARD_API int mockcard_add_application(mockcard_t *t, uint32_t aid, int key_type, uint8_t num_keys) {
    if (find_app(t, aid) != NULL) {
        return NXPSC_E_PARAM;
    }
    if (add_app(t, aid, (nxpsc_keytype_t)key_type, num_keys) == NULL) {
        return NXPSC_E_MEMORY;
    }
    if (aid != 0x000000 && t->mock.app_count < MOCK_MAX_APPS) {
        mock_app_t *app = &t->mock.apps[t->mock.app_count++];
        memset(app, 0, sizeof(*app));
        app->present = true;
        app->aid = aid;
        app->key_settings = 0x0B;
        app->num_keys = num_keys;
        app->key_type = (uint8_t)key_type;
    }
    return NXPSC_OK;
}

MOCKCARD_API bool mockcard_has_application(mockcard_t *t, uint32_t aid) {
    return find_app(t, aid) != NULL;
}

// what a key reads as after a successful ChangeKey. takes == false models a
// card that acknowledges ChangeKey and keeps the old key
MOCKCARD_API void mockcard_set_change_key_result(mockcard_t *t, bool takes, int key_type,
                                           const uint8_t *key, size_t key_len, uint8_t key_version) {
    t->change_takes = takes;
    t->change_type = (nxpsc_keytype_t)key_type;
    memset(t->change_key, 0, sizeof(t->change_key));
    if (key != NULL && key_len <= sizeof(t->change_key)) {
        memcpy(t->change_key, key, key_len);
    }
    // the version travels inside the cryptogram, so the card side is told it
    t->mock.change_key_version = key_version;
}

// 1 when the key equals the one given, 0 when it differs, negative when absent
MOCKCARD_API int mockcard_key_equals(mockcard_t *t, uint32_t aid, uint8_t key_no,
                               const uint8_t *key, size_t key_len) {
    mockcard_app_t *app = find_app(t, aid);
    if (app == NULL || key_no >= app->num_keys || key_len > NXPSC_MAX_KEY_SIZE) {
        return NXPSC_E_PARAM;
    }
    return memcmp(app->key[key_no], key, key_len) == 0 ? 1 : 0;
}

// The AppTransactionMACKey reaches a real card enciphered inside
// CreateTransactionMACFile. The mock does not decipher command data, so the
// caller states the key here and the card side uses it to compute the
// transaction MAC; the file itself still has to be created on the card.
MOCKCARD_API int mockcard_set_transaction_mac_key(mockcard_t *t, const uint8_t *key, size_t len) {
    if (t == NULL || key == NULL || len != sizeof(t->mock.tm_key)) {
        return NXPSC_E_PARAM;
    }
    memcpy(t->mock.tm_key, key, len);
    return NXPSC_OK;
}

// How many transactions the card has committed, i.e. the counter it reported
// last. Zero until the transaction MAC file exists and a commit has happened
MOCKCARD_API uint32_t mockcard_transaction_counter(const mockcard_t *t) {
    return (t == NULL) ? 0 : t->mock.tmc;
}

// A file the card already holds, as if an earlier run had created it. type is
// nxpsc_filetype_t, access is packed as on the wire (read, write, read/write,
// change, four bits each, most significant first)
MOCKCARD_API int mockcard_add_file(mockcard_t *t, uint8_t file_no, uint8_t type, uint8_t comm,
                                   uint16_t access, uint32_t size, uint32_t record_size,
                                   uint32_t max_records) {
    if (t == NULL) {
        return NXPSC_E_PARAM;
    }
    for (size_t i = 0; i < t->mock.file_count; i++) {
        if (t->mock.files[i].file_no == file_no) {
            return NXPSC_E_PARAM;      // already there
        }
    }
    if (t->mock.file_count >= MOCK_MAX_FILES) {
        return NXPSC_E_MEMORY;
    }

    mock_file_t *file = &t->mock.files[t->mock.file_count++];
    memset(file, 0, sizeof(*file));
    file->file_no = file_no;
    file->type = type;
    file->comm = comm;
    file->access = access;
    file->size = size;
    file->record_size = record_size;
    file->max_records = max_records;
    return NXPSC_OK;
}

// What the card reports for its transaction MAC file. Its settings reach a real
// card inside CreateTransactionMACFile, enciphered, so the mock is told them
MOCKCARD_API int mockcard_set_transaction_mac_file(mockcard_t *t, uint8_t file_no, uint8_t comm,
                                                   uint16_t access) {
    if (t == NULL) {
        return NXPSC_E_PARAM;
    }
    t->mock.tm_file_no = file_no;
    t->mock.tm_file_comm = comm;
    t->mock.tm_file_access = access;
    return NXPSC_OK;
}

// The transaction MAC feature is on, as it would be on a card whose file an
// earlier run created
MOCKCARD_API void mockcard_enable_transaction_mac(mockcard_t *t) {
    if (t != NULL) {
        t->mock.tm_file = true;
    }
}

MOCKCARD_API void mockcard_set_signature(mockcard_t *t, const uint8_t *sig, size_t len) {
    t->has_signature = (sig != NULL && len == sizeof(t->signature));
    if (t->has_signature) {
        memcpy(t->signature, sig, len);
    }
}

// the card leaves the field at the first frame carrying this native command,
// either before the card acts on it or after it has
MOCKCARD_API void mockcard_tear_on(mockcard_t *t, uint8_t native_cmd, bool after_execute) {
    t->tear_cmd = native_cmd;
    t->tear_after_execute = after_execute;
}

MOCKCARD_API bool mockcard_torn(mockcard_t *t) {
    return t->torn;
}

// the card comes back: fresh field, no session, no tear pending
MOCKCARD_API void mockcard_reinsert(mockcard_t *t) {
    t->torn = false;
    t->tear_cmd = 0;
    drop_session(t);
    t->mock.selected_aid = 0;
}

static int exchange(mockcard_t *t, bool wrapped, uint8_t cmd, const uint8_t *data, size_t data_len,
                    const uint8_t *tx, size_t tx_len, uint8_t *rx, size_t cap, size_t *rx_len) {
    switch (cmd) {
        case 0x5A: {                            // SelectApplication
            if (data_len < 3) {
                return status_only(wrapped, 0x7E, rx, cap, rx_len);
            }
            uint32_t aid = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16);
            drop_session(t);
            if (find_app(t, aid) == NULL) {
                return status_only(wrapped, 0xA0, rx, cap, rx_len);
            }
            break;
        }

        case 0x0A:                              // every authenticate flavour
        case 0x1A:
        case 0xAA:
        case 0x71:
        case 0x77: {
            uint8_t key_no = (data_len > 0) ? (uint8_t)(data[0] & 0x0F) : 0;
            mockcard_app_t *app = find_app(t, t->mock.selected_aid);
            if (app == NULL || key_no >= app->num_keys) {
                drop_session(t);
                return status_only(wrapped, 0x40, rx, cap, rx_len);      // NO_SUCH_KEY
            }
            t->mock.auth_key_type = app->key_type[key_no];
            memcpy(t->mock.auth_key, app->key[key_no], NXPSC_MAX_KEY_SIZE);
            break;
        }

        case 0x3C:                              // Read_Sig
            if (t->has_signature) {
                if (cap < sizeof(t->signature) + 2) {
                    return NXPSC_E_LENGTH;
                }
                if (wrapped) {
                    memcpy(rx, t->signature, sizeof(t->signature));
                    rx[sizeof(t->signature)] = 0x91;
                    rx[sizeof(t->signature) + 1] = 0x00;
                    *rx_len = sizeof(t->signature) + 2;
                } else {
                    rx[0] = 0x00;
                    memcpy(rx + 1, t->signature, sizeof(t->signature));
                    *rx_len = sizeof(t->signature) + 1;
                }
                return NXPSC_OK;
            }
            break;

        case 0xCA: {                            // CreateApplication
            if (data_len < 5) {
                return status_only(wrapped, 0x7E, rx, cap, rx_len);
            }
            uint32_t aid = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16);
            if (find_app(t, aid) != NULL) {
                if (t->mock.secure_active) {
                    // the mock frames an in-session error and drops the session,
                    // exactly as the PICC does
                    t->mock.reject_cmd = cmd;
                    t->mock.reject_status = 0xDE;
                    break;
                }
                return status_only(wrapped, 0xDE, rx, cap, rx_len);      // DUPLICATE_ERROR
            }
            int rc = mock_transceive(&t->mock, tx, tx_len, rx, cap, rx_len);
            if (rc == NXPSC_OK && answered_ok(wrapped, rx, *rx_len)) {
                uint8_t nk = data[4];
                nxpsc_keytype_t type = (nk & 0x80) ? NXPSC_KEY_AES128
                                     : (nk & 0x40) ? NXPSC_KEY_3K3DES
                                     : NXPSC_KEY_2K3DES;
                if (add_app(t, aid, type, (uint8_t)(nk & 0x0F)) == NULL) {
                    return NXPSC_E_MEMORY;
                }
            }
            return rc;
        }

        case 0xC4: {                            // ChangeKey
            uint8_t key_no = (data_len > 0) ? (uint8_t)(data[0] & 0x0F) : 0;
            int rc = mock_transceive(&t->mock, tx, tx_len, rx, cap, rx_len);
            if (rc == NXPSC_OK && answered_ok(wrapped, rx, *rx_len) && t->change_takes) {
                mockcard_app_t *app = find_app(t, t->mock.selected_aid);
                if (app != NULL && key_no < app->num_keys) {
                    app->key_type[key_no] = t->change_type;
                    memcpy(app->key[key_no], t->change_key, NXPSC_MAX_KEY_SIZE);
                }
            }
            return rc;
        }

        default:
            break;
    }

    return mock_transceive(&t->mock, tx, tx_len, rx, cap, rx_len);
}

MOCKCARD_API int mockcard_transceive(mockcard_t *t, const uint8_t *tx, size_t tx_len,
                               uint8_t *rx, size_t cap, size_t *rx_len) {
    if (t == NULL || tx == NULL || rx == NULL || rx_len == NULL) {
        return NXPSC_E_PARAM;
    }
    if (t->torn) {
        return NXPSC_E_TRANSPORT;
    }

    uint8_t cmd = 0;
    const uint8_t *data = NULL;
    size_t data_len = 0;
    bool wrapped = false;
    if (parse_frame(tx, tx_len, &cmd, &data, &data_len, &wrapped) == false) {
        // real ISO 7816-4 commands go straight through
        return mock_transceive(&t->mock, tx, tx_len, rx, cap, rx_len);
    }

    if (t->tear_cmd != 0 && cmd == t->tear_cmd) {
        if (t->tear_after_execute) {
            size_t discard = 0;
            (void)exchange(t, wrapped, cmd, data, data_len, tx, tx_len, rx, cap, &discard);
        }
        t->torn = true;
        drop_session(t);
        return NXPSC_E_TRANSPORT;
    }

    return exchange(t, wrapped, cmd, data, data_len, tx, tx_len, rx, cap, rx_len);
}
