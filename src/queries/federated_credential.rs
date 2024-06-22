use sqlx::PgExecutor;
use uuid::Uuid;
use crate::auth::oauth::AuthProvider;

pub struct FederatedCredential;

impl FederatedCredential {
    pub async fn insert(
        db: impl PgExecutor<'_>,
        user_id: impl AsRef<Uuid>,
        auth_provider: &AuthProvider,
        subject_id: impl AsRef<str>,
    ) -> sqlx::Result<()> {
        query!(
            r#"
    INSERT INTO federated_credentials (user_id, provider, subject_id)
    VALUES ($1, $2, $3)
    "#,
            user_id.as_ref(),
            auth_provider as _,
            subject_id.as_ref()
        )
            .execute(db)
            .await?;
        Ok(())
    }
    pub async fn select_user_id(
        db: impl PgExecutor<'_>,
        provider: &AuthProvider,
        subject_id: &str,
    ) -> sqlx::Result<Option<Uuid>> {
        Ok(query!(
            r#"
    SELECT user_id
    FROM federated_credentials
    WHERE provider = $1 AND subject_id = $2
    "#,
            provider as _,
            subject_id
        )
            .fetch_optional(db)
            .await?
            .map(|r| r.user_id))
    }
}
