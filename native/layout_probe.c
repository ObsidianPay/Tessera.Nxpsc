//-----------------------------------------------------------------------------
// layout_probe - the C compiler's view of libnxpsc's public structs
//
// Prints one line per struct ("name size N") and per field
// ("name.field offset N"). The managed mirrors in Tessera.Nxpsc are checked
// against this output by the test suite, on every platform CI builds for.
//-----------------------------------------------------------------------------

#include <stddef.h>
#include <stdio.h>

#include "nxpsc/nxpsc.h"

#define SIZE(t) printf("%s size %zu\n", #t, sizeof(t))
#define OFF(t, f) printf("%s.%s offset %zu\n", #t, #f, offsetof(t, f))

int main(void) {
    SIZE(nxpsc_key_t);
    OFF(nxpsc_key_t, type); OFF(nxpsc_key_t, data); OFF(nxpsc_key_t, version);

    SIZE(nxpsc_transport_t);
    OFF(nxpsc_transport_t, ctx); OFF(nxpsc_transport_t, transceive);
    OFF(nxpsc_transport_t, get_uid); OFF(nxpsc_transport_t, reselect);

    SIZE(nxpsc_version_t);
    OFF(nxpsc_version_t, hw_vendor); OFF(nxpsc_version_t, hw_protocol);
    OFF(nxpsc_version_t, sw_vendor); OFF(nxpsc_version_t, sw_protocol);
    OFF(nxpsc_version_t, uid); OFF(nxpsc_version_t, batch);
    OFF(nxpsc_version_t, week); OFF(nxpsc_version_t, year); OFF(nxpsc_version_t, has_batch_extra);

    SIZE(nxpsc_access_t);
    OFF(nxpsc_access_t, read); OFF(nxpsc_access_t, write);
    OFF(nxpsc_access_t, read_write); OFF(nxpsc_access_t, change);

    SIZE(nxpsc_file_settings_t);
    OFF(nxpsc_file_settings_t, type); OFF(nxpsc_file_settings_t, options); OFF(nxpsc_file_settings_t, comm);
    OFF(nxpsc_file_settings_t, access); OFF(nxpsc_file_settings_t, size); OFF(nxpsc_file_settings_t, lower_limit);
    OFF(nxpsc_file_settings_t, upper_limit); OFF(nxpsc_file_settings_t, value); OFF(nxpsc_file_settings_t, limited_credit);
    OFF(nxpsc_file_settings_t, record_size); OFF(nxpsc_file_settings_t, max_records); OFF(nxpsc_file_settings_t, cur_records);
    OFF(nxpsc_file_settings_t, sdm_enabled); OFF(nxpsc_file_settings_t, sdm_options);

    SIZE(nxpsc_app_t);
    OFF(nxpsc_app_t, aid); OFF(nxpsc_app_t, iso_fid); OFF(nxpsc_app_t, df_name); OFF(nxpsc_app_t, df_name_len);
    OFF(nxpsc_app_t, key_settings); OFF(nxpsc_app_t, num_keys); OFF(nxpsc_app_t, key_type); OFF(nxpsc_app_t, iso_fid_enabled);

    SIZE(nxpsc_app_config_t);
    OFF(nxpsc_app_config_t, key_settings); OFF(nxpsc_app_config_t, num_keys); OFF(nxpsc_app_config_t, key_type);
    OFF(nxpsc_app_config_t, iso_fid_enabled); OFF(nxpsc_app_config_t, iso_fid); OFF(nxpsc_app_config_t, df_name);
    OFF(nxpsc_app_config_t, df_name_len); OFF(nxpsc_app_config_t, num_key_sets); OFF(nxpsc_app_config_t, key_set_version);
    OFF(nxpsc_app_config_t, max_key_size); OFF(nxpsc_app_config_t, key_set_settings);
    OFF(nxpsc_app_config_t, specific_vc_keys); OFF(nxpsc_app_config_t, specific_capability_data);

    SIZE(nxpsc_delegate_info_t);
    OFF(nxpsc_delegate_info_t, dam_slot_version); OFF(nxpsc_delegate_info_t, quota_limit);
    OFF(nxpsc_delegate_info_t, free_blocks); OFF(nxpsc_delegate_info_t, aid);

    SIZE(nxpsc_picc_config_t);
    OFF(nxpsc_picc_config_t, disable_format); OFF(nxpsc_picc_config_t, random_uid);
    OFF(nxpsc_picc_config_t, pc_mandatory); OFF(nxpsc_picc_config_t, auth_vc_mandatory);

    SIZE(nxpsc_sdm_settings_t);
    OFF(nxpsc_sdm_settings_t, enabled); OFF(nxpsc_sdm_settings_t, uid_mirror); OFF(nxpsc_sdm_settings_t, counter_mirror);
    OFF(nxpsc_sdm_settings_t, read_counter_limit); OFF(nxpsc_sdm_settings_t, enc_file_data);
    OFF(nxpsc_sdm_settings_t, meta_read_key); OFF(nxpsc_sdm_settings_t, file_read_key); OFF(nxpsc_sdm_settings_t, counter_ret_key);
    OFF(nxpsc_sdm_settings_t, uid_offset); OFF(nxpsc_sdm_settings_t, counter_offset); OFF(nxpsc_sdm_settings_t, picc_data_offset);
    OFF(nxpsc_sdm_settings_t, mac_input_offset); OFF(nxpsc_sdm_settings_t, enc_offset); OFF(nxpsc_sdm_settings_t, enc_length);
    OFF(nxpsc_sdm_settings_t, mac_offset); OFF(nxpsc_sdm_settings_t, read_counter_limit_value);
    return 0;
}
