//! Test-support re-exports behind the `test-support` feature: the GUI's
//! headless smoke test drives the real admin router (auth, save-time
//! endpoint validation, live registries) through the HTTP client, so these
//! helpers must be reachable from a dev-dependency context. Not compiled
//! into normal builds.

pub mod testing {
    pub use crate::testing::ADMIN_TEST_KEY;
    pub use crate::testing::AdminTestServer;
    pub use crate::testing::TestDatabase;
    pub use crate::testing::spawn_admin;
}
