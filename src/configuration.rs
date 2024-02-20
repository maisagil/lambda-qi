use secrecy::Secret;

#[derive(serde::Deserialize, Clone, Debug)]
pub struct Settings {
    pub qi_client: QIClientSettings,
}

#[derive(serde::Deserialize, Clone, Debug)]
pub struct QIClientSettings {
    pub base_url: String,
    pub private_key: Secret<String>,
    pub private_key_password: Secret<String>,
    pub api_key: Secret<String>,
    pub provider_pub_key: String,
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine current directory");
    let configuration_directory = base_path.join("configuration");

    let enviroment: Environment = std::env::var("APP_ENVIROMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to parse APP_ENVIROMENT.");
    let enviroment_filename = format!("{}.yaml", enviroment.as_str());
    // Initialise our configuration reader
    let settings = config::Config::builder()
        .add_source(config::File::from(
            configuration_directory.join("base.yaml"),
        ))
        // Add configuration values from a file named `configuration.yaml`.
        .add_source(config::File::from(
            configuration_directory.join(enviroment_filename),
        ))
        .add_source(
            config::Environment::with_prefix("APP")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?;
    // Try to convert the configuration values it read into our Settings type
    settings.try_deserialize::<Settings>()
}

pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} is not a supported environment. \
                Use either `local` or `production`.",
                other
            )),
        }
    }
}