pub fn check_contract_codecs_current_workspace() -> Result<(), String> {
    tidefs_schema_codec_vfs::contract_codec_self_check()
        .map_err(|err| format!("contract codec check failed: {err:?}"))?;
    println!(
        "contract codecs ok: request envelope and completion v1 golden vectors plus reserved-field rejection"
    );
    Ok(())
}
