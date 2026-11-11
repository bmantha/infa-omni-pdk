use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "blockOnUnknownClassification")]
    pub block_on_unknown_classification: Option<bool>,
    #[serde(
        alias = "cdgcBaseApiUrl",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub cdgc_base_api_url: pdk::hl::Service,
    #[serde(
        alias = "cdgcLoginUrl",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub cdgc_login_url: pdk::hl::Service,
    #[serde(alias = "cdgcOrgPassword")]
    pub cdgc_org_password: String,
    #[serde(alias = "cdgcOrgUsername")]
    pub cdgc_org_username: String,
    #[serde(alias = "discloseClassificationDetails")]
    pub disclose_classification_details: Option<bool>,
    #[serde(alias = "distributed")]
    pub distributed: Option<bool>,
    #[serde(alias = "failOpenOnCdgcError")]
    pub fail_open_on_cdgc_error: Option<bool>,
    #[serde(alias = "governedColumnIds")]
    pub governed_column_ids: String,
    #[serde(alias = "maxAllowedClassification")]
    pub max_allowed_classification: String,
    #[serde(alias = "refreshIntervalSeconds")]
    pub refresh_interval_seconds: Option<i64>,
    #[serde(alias = "timeout")]
    pub timeout: Option<i64>,
}
