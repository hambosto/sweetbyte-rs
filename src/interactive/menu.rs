use super::workflow::Workflow;
use anyhow::Result;

pub fn run() -> Result<()> {
    let workflow = Workflow::new();
    workflow.run()
}
