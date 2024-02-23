pub mod configuration;
mod qitech;

use configuration::get_configuration;
use qitech::{AskBalanceRequest, QiTechProvider};
use std::sync::OnceLock;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

static INSTANCE: OnceLock<QiTechProvider> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    dotenv::dotenv().ok();

    let configuration = get_configuration().expect("Failed to read configuration.");
    let provider = QiTechProvider::new(configuration.qi_client);
    INSTANCE.set(provider).ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    let request = AskBalanceRequest {
        document_number: "05577889944".to_string(),
    };
    let provider = INSTANCE.get().unwrap();
    match provider.ask_for_balance(request).await {
        Ok(response) => println!("{}", &response),
        Err(e) => println!("{}", e),
    };
    Ok(())
}
