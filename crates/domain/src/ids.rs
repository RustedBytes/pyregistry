use uuid::Uuid;

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub fn into_inner(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self(Uuid::new_v4())
            }
        }
    };
}

id_newtype!(TenantId);
id_newtype!(AdminUserId);
id_newtype!(TokenId);
id_newtype!(ProjectId);
id_newtype!(ReleaseId);
id_newtype!(ArtifactId);
id_newtype!(TrustedPublisherId);
