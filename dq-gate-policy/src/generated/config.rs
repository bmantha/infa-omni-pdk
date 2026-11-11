use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "allowInsecureLocalServices")]
    pub allow_insecure_local_services: Option<bool>,
    #[serde(alias = "blockOnUnknownScore")]
    pub block_on_unknown_score: Option<bool>,
    #[serde(alias = "blockThreshold")]
    pub block_threshold: f64,
    #[serde(alias = "cdgcAssetId")]
    pub cdgc_asset_id: String,
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
    #[serde(alias = "discloseScoreDetails")]
    pub disclose_score_details: Option<bool>,
    #[serde(alias = "distributed")]
    pub distributed: Option<bool>,
    #[serde(alias = "failOpenOnCdgcError")]
    pub fail_open_on_cdgc_error: Option<bool>,
    #[serde(alias = "refreshIntervalSeconds")]
    pub refresh_interval_seconds: Option<i64>,
    #[serde(alias = "scoreAggregation")]
    pub score_aggregation: Option<String>,
    #[serde(alias = "timeout")]
    pub timeout: Option<i64>,
    #[serde(alias = "warnThreshold")]
    pub warn_threshold: f64,
}
