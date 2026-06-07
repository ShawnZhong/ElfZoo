use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use rayon::prelude::*;

#[derive(ClapArgs)]
pub struct Options {
    #[arg(long, default_value_t = default_jobs())]
    jobs: usize,

    #[arg(long, help = "Rewrite current-schema output files")]
    force: bool,

    #[arg(long, help = "Limit inputs processed; useful for smoke tests")]
    limit: Option<usize>,
}

impl Options {
    pub fn jobs(&self) -> usize {
        self.jobs.max(1)
    }

    pub fn force(&self) -> bool {
        self.force
    }

    pub fn apply_limit<T>(&self, items: &mut Vec<T>) {
        if let Some(limit) = self.limit {
            items.truncate(limit);
        }
    }
}

pub fn run_items<T, R, F>(
    args: &Options,
    command: &str,
    noun: &str,
    items: &[T],
    analyze: F,
) -> Result<Vec<R>>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> Result<R> + Sync,
{
    let total = items.len();
    eprintln!("{command}: found {total} {noun} (jobs={})", args.jobs());
    if total == 0 {
        return Ok(Vec::new());
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs())
        .build()
        .context("building worker pool")?;
    let done = AtomicUsize::new(0);
    pool.install(|| {
        items
            .par_iter()
            .map(|item| {
                let result = analyze(item)?;
                let current = done.fetch_add(1, Ordering::Relaxed) + 1;
                if current == total || current <= 10 || current % 100 == 0 {
                    eprintln!(
                        "{command}: {current}/{total} {noun} ({:.1}%)",
                        current as f64 / total as f64 * 100.0
                    );
                }
                Ok(result)
            })
            .collect()
    })
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}
